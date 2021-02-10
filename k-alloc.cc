#include "kernel.hh"
#include "k-lock.hh"
#include "k-list.hh"

#define MIN_ORDER 11
#define MAX_ORDER 21

struct page {
    list_links links_;
    int order;
    int page;
    bool used;
};
static page pages[MEMSIZE_PHYSICAL / PAGESIZE];

static list<page, &page::links_> free_heads[MAX_ORDER - MIN_ORDER + 1];

static spinlock page_lock;


// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc() {
    // initialize pages array
    memset(pages, 0, sizeof(pages));

    for (auto range = physical_ranges.begin(); range->first() < physical_ranges.limit(); range++) {
        for (uintptr_t addr = range->first(); addr < range->last(); ) {
            int page = addr/PAGESIZE;
            pages[page].page = page;
            for (int order = MAX_ORDER; order >= MIN_ORDER; order--) {
                if (addr + (1 << order) <= range->last() && addr % (1 << order) == 0) {
                    // biggest order that can fit between `addr` and the end of the range
                    pages[page].order = order;

                    if (!(pages[page].used = range->type() != mem_available)) {
                        // range is free
                        free_heads[order - MIN_ORDER].push_back(&pages[page]);
                    }

                    // next block
                    addr += 1UL << order;
                    break;
                }
            }
        }
    }
}


// kalloc(sz)
//    Allocate and return a pointer to at least `sz` contiguous bytes of
//    memory. Returns `nullptr` if `sz == 0` or on failure.
//
//    The caller should initialize the returned memory before using it.
//    The handout allocator sets returned memory to 0xCC (this corresponds
//    to the x86 `int3` instruction and may help you debug).
//
//    If `sz` is a multiple of `PAGESIZE`, the returned pointer is guaranteed
//    to be page-aligned.
//
//    The handout code does not free memory and allocates memory in units
//    of pages.
void* kalloc(size_t sz) {
    if (sz == 0) {
        return nullptr;
    }
    sz = max(sz, 1UL << MIN_ORDER);

    int order = msb(sz - 1);
    if (order > MAX_ORDER) {
        log_printf("%d bytes of memory requested, maximum is %d\n", sz, 1UL << MAX_ORDER);
        return nullptr;
    }

    // lock the pages
    spinlock_guard guard(page_lock);
    while (free_heads[order - MIN_ORDER].empty()) {
        int next_order = order;
        do {
            next_order++;
            if (next_order > MAX_ORDER) {
                return nullptr;
            }
        } while (free_heads[next_order - MIN_ORDER].empty());

        page* splittable = free_heads[next_order - MIN_ORDER].pop_front();

        // split the block
        splittable->order--;
        // original becomes left buddy
        free_heads[next_order - MIN_ORDER - 1].push_back(splittable);

        // right buddy
        int right_page = splittable->page + (1 << (splittable->order - msb(PAGESIZE - 1)));
        page* right_buddy = &pages[right_page];
        right_buddy->page = right_page;
        right_buddy->order = splittable->order;
        right_buddy->used = false;
        free_heads[right_buddy->order - MIN_ORDER].push_back(right_buddy);
    }

    page* block = free_heads[order - MIN_ORDER].pop_front();
    block->used = true;
    uintptr_t pa = block->page * PAGESIZE;
    asan_mark_memory(pa, sz, false);
    return reinterpret_cast<void*>(pa2ka(pa));
}


// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr) {
    if (!ptr) {
        return;
    }

    // lock the pages
    spinlock_guard guard(page_lock);

    // all allocations should be page-aligned
    assert(ka2pa(ptr) % PAGESIZE == 0);
    int page = ka2pa(ptr)/PAGESIZE;

    pages[page].used = false;
    int order = pages[page].order;

    while (true) {
        // find its buddy either to the left or to the right
        int buddy = (page*PAGESIZE
                     + (1 << order)*(((page*PAGESIZE)% (1 << (order + 1)) == 0)
                                     ? 1
                                     : -1)
                     )/PAGESIZE;

        if (pages[buddy].used) {
            // buddy already in use
            break;
        }

        if (pages[buddy].order == MAX_ORDER) {
            // buddy can't be merged further
            break;
        }

        if (pages[buddy].order != order) {
            // can't merge pages of different orders
            break;
        }

        if (!pages[buddy].links_.next_ || !pages[buddy].links_.prev_) {
            // buddy not reachable (outside of a block)
            break;
        }

        // merge
        free_heads[pages[buddy].order - MIN_ORDER].erase(&pages[buddy]);
        // so long, old buddy
        memset(&pages[max(page, buddy)], 0, sizeof(page));
        pages[min(page, buddy)].order++;

        page = min(page, buddy);
    }

    free_heads[order - MIN_ORDER].push_back(&pages[page]);

    asan_mark_memory(page * PAGESIZE, 1U << order, true);
}

int test_kalloc() {
    // specification tests
    assert(!kalloc(0));
    kfree(nullptr);

    // stress-testing
    for (int i = 0; i < 100; i++) {
        int size = rand(1 << MIN_ORDER, 1 << MAX_ORDER);
        log_printf("testing allocation and freeing of %d bytes (order %d)...\n", size, msb(size - 1));
        void* ptr = kalloc(size);
        kfree(ptr);
    }

    log_printf("all kalloc tests passed!\n");

    return 0;
}


// operator new, operator delete
//    Expressions like `new (std::nothrow) T(...)` and `delete x` work,
//    and call kalloc/kfree.
void* operator new(size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new(size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void operator delete(void* ptr) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}
