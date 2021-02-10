CS 161 Problem Set 1 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset1collab.md`.

Answers to written questions
----------------------------
### Part A
1. Right now, the maximum size supported by `kalloc()` is `PAGESIZE` = 1 << 12 = **4096** (4 KiB).
2. The first address returned by `kalloc()` is **`0x002000`**.  
    `kalloc()` returns the first page in `physical_ranges` that is marked as available, starting from `next_free_pa`. As a `static` variable, `next_free_pa` is initialized to 0. However, in `init_physical_ranges()` in k-init.cc, the page at address `0x0` is marked as reserved, so that the null pointer, whose address is `0x0`, can never be dereferenced:
    ```cpp
    // 0 page is reserved (because nullptr)
    physical_ranges.set(0, PAGESIZE, mem_reserved);
    ```
    Since the first page is reserved in this way, the `while` loop moves to the next memory range one 4 KiB page later at `0x002000`, which is free.
3. **`0x1ff000`**, the address of the very last 4 KiB page that can fit into the current amount of physical memory.
4. `kalloc()` returns **physical addresses**. k-alloc.c:38 uses the `physical_ranges` object to get an iterator to start searching for the next page marked as available, meaning that the returned pointer is being treated as an address into physical memory:
    ```cpp
    auto range = physical_ranges.find(next_free_pa);
    ```
5. Define `MEMSIZE_PHYSICAL` as `0x300000` at kernel.hh:191, like so (diff):
    ```diff
    --- a/kernel.hh
    +++ b/kernel.hh
    @@ -191 +191 @@
    -#define MEMSIZE_PHYSICAL        0x200000
    +#define MEMSIZE_PHYSICAL        0x300000
    ```
    This works when tested.
6. 
    ```cpp
    for (; next_free_pa < physical_ranges.limit(); next_free_pa += PAGESIZE) {
        if (physical_ranges.type(next_free_pa) == mem_available) {
            ptr = pa2kptr<void*>(next_free_pa);
            next_free_pa += PAGESIZE;
            break;
        }
    }
    ```
7. The loop using the iterator returned by `find()` only needs to loop once for each contiguous range of pages in memory that are all marked the same type, so it runs in ***_O(R)_** time, where _R_ is the number of contiguous ranges. In contrast, the loop using `type()` needs to check every page from `next_free_pa` onwards until it finds an available page, and cannot skip over long contiguously-marked ranges of pages. Worse, `type()` calls `find()` in k-memrange.hh, which loops through all the ranges to find the type of a given page, so the `type()` loop has an overall time complexity of **_O(N×R)_** where _N_ is the number of pages and _R_ is the number of contiguous ranges.  
    For example, assuming `0x200000` bytes of physical memory, and the absolute worst case of `next_free_pa == 0`, with every page in memory alternating between being marked `mem_reserved` and being marked `mem_kernel`: there are 256 pages, and the length of the longest contiguous range is 1, so there are also 256 ranges. In this case, the `find()` loop has to run 256 _O(1)_ checks to find that there is no free memory left. However, the `type()` loop has to loop 256 times, and during each loop needs to iterate through all the previous pages as well in the `type()` call to find each page's type, which results in a total of Σᵢ²⁵⁶(i)=32640 _O(1)_ checks.
    Additionally, in the best case for the `find()` loop, where all of memory is marked as `mem_reserved`: the `find()` loop only needs to do 1 loop since all of memory is one contiguously-marked range of reserved pages, while the `type()` loop still needs to loop 256 times—once for each page.
8.  During a `kalloc()` call, another thread that calls `kalloc()` could execute the `while` loop at the same time as the first if there was no `page_lock`. Since both threads would be reading and modifying the same `static` `next_free_pa` variable, the second thread could execute the `// move to next range` block while the first is in the `// use this page` block. The second thread would then overwrite the value of `next_free_pa` that the first thread was expecting to match with the start of its current `range`, and replace it with the start of the next `range` that the second thread was going to check, which could cause the first thread to return a pointer to memory that is not actually free (!).

### Part B
1. k-memviewer.cc:86:
    ```cpp
    mark(pa, f_kernel);
    ```
2. k-memviewer.cc:96:
    ```cpp
    mark(ka2pa(p), f_kernel | f_process(pid));
    ```
3. The `ptiter` loop walks through the pages of memory used to store each process’ virtual-to-physical page tables themselves, whereas the `vmiter` loop walks the physical addresses of the virtual memory pages that are mapped by the aforementioned page tables. Level 0 pages are involved in both loops. If the pages marked by the `ptiter` loop were user-accessible, user-mode processes would be able to edit their own page tables and remap their virtual memory to areas of physical memory belonging to other processes or the kernel, breaking process isolation and many memory security guarantees.
4. `mem_available`, because at this stage in the boot process, no processes have actually allocated any memory yet.
5. QEMU goes blank, since now the vmiter has to iterate through every page of virtual memory rather than skipping over contiguous unallocated ranges. The virtual memory space of each process is very large—usually even larger than the physical memory—so this takes an extraordinarily long time and blocks the memviewer.
6. Those pages are allocated to store the process descriptor for the idle task, which runs when the CPU has nothing else to do. The number of these pages increases with `NCPU` because each CPU has its own idle task. Additionally, there is one page that holds the memviewer’s memory map itself, which is not accounted for by the memviewer.
7. I marked the physical address of the `v_` array holding the memviewer’s memory map, and additionally marked the page of the idle task process description associated with each CPU according to `struct cpustate`. Later, when I extended `kalloc` to support sizes larger than `PAGESIZE`, the `struct ahcistate` for the SATA disk was being allocated without failure and also needed to be marked. All these pages were marked as kernel-restricted because the memviewer lives in kernel space and the idle task process descriptors are kernel structures.

### Part C
1. `boot()` is called by bootentry.S:106 after switching out of compatibility mode so that the rest of the bootloader can run:
    ```asm
        ljmp    $SEGSEL_BOOT_CODE, $boot
    ```
2. `kernel_start(const char*)` is called by k-exception.S:35 during boot after the bootloader has loaded the kernel and k-exception.S has finished setting up the stack:
    ```asm
        jmp _Z12kernel_startPKc
    ```
3. `proc::exception(regstate*)` is called by k-exception.S:143 after an exception is thrown and k-exception.S has copied the registers into a `struct regstate`:
    ```asm
        call _ZN4proc9exceptionEP8regstate
    ```
4. `proc::syscall(regstate*)` is called by k-exception.S:228 after a syscall has been made and k-exception.S has copied the registers into a `struct regstate`:
    ```asm
        call _ZN4proc7syscallEP8regstate
    ```
5. `cpustate::schedule(proc*)` is called by k-exception.S:293 so that the scheduler can find another process to run on the CPU after one has yielded:
    ```asm
        jmp _ZN8cpustate8scheduleEP4proc
    ```
6. `cpustate::init_ap()` is called by k-exception.S:485-486 when initializing an Application Processor:
    ```asm
        movabsq $_ZN8cpustate7init_apEv, %rbx
        jmp *%rbx
    ```
7. `idle()` is called by k-cpu.cc:138 via `proc::init_kernel` as the entry point to the idle task, which gets its own stack from `proc::init_kernel` because it is a new kernel process:
    ```cpp
        idle_task_->init_kernel(-1, idle);
    ```

### Part D
Done.

### Part E
Done.

### Part F
1. Done. The system call is called `sys_stackoverflow()`.
2. Done.
3. `-Wstack-usage` does indeed detect the problem in the stackoverflow syscall when set to anything lower than 16400 bytes. It may be useful to set it to `PAGESIZE`, since it is highly unlikely that correct kernel code would intentionally use a whole page worth of memory on the stack.
    ```
    kernel.cc:162:5: warning: stack usage is 16400 bytes [-Wstack-usage=]
     int stackoverflow() {
         ^~~~~~~~~~~~~
    ```

### Part G
Done.

Grading notes
-------------
