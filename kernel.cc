#include "kernel.hh"
#include "k-ahci.hh"
#include "k-apic.hh"
#include "k-chkfs.hh"
#include "k-chkfsiter.hh"
#include "k-devices.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"

// kernel.cc
//
//    This is the kernel.

// # timer interrupts so far on CPU 0
std::atomic<unsigned long> ticks;

// display type; initially KDISPLAY_CONSOLE
std::atomic<int> kdisplay;

// keep it safe
int canary = rand();

static wait_queue waitpidq;

#define TIMERQS 5
wait_queue timing_wheel[TIMERQS];

static void tick();
static void boot_process_start(pid_t pid, const char* program_name);


void init() {
    while (true) {
        if (current()->waitpid(0) == E_CHILD) {
            process_halt();
        }
    }
}


// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

void kernel_start(const char* command) {
    init_hardware();
    console_clear();

    // set up process descriptors
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i] = nullptr;
    }

    // start init
    proc* initproc = knew<proc>();
    initproc->init_kernel(1, init);
    {
        spinlock_guard guard(ptable_lock);
        ptable[1] = initproc;
    }
    cpus[0].enqueue(initproc);

    // start first process
    boot_process_start(2, CHICKADEE_FIRST_PROCESS);

    // start running processes
    cpus[0].schedule(nullptr);
}


// boot_process_start(pid, name)
//    Load application program `name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.
//    Only called at initial boot time.

void boot_process_start(pid_t pid, const char* name) {
    // look up process image in initfs
    memfile_loader ld(memfile::initfs_lookup(name), kalloc_pagetable());
    assert(ld.memfile_ && ld.pagetable_);
    int r = proc::load(ld);
    assert(r >= 0);

    // allocate process, initialize memory
    proc* p = knew<proc>();
    p->init_user(pid, ld.pagetable_);
    p->regs_->reg_rip = ld.entry_rip_;

    void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);
    vmiter(p, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);
    vmiter(p, ktext2pa(console)).map(ktext2pa(console), PTE_PWU);
    p->regs_->reg_rsp = MEMSIZE_VIRTUAL;

    // add to process table (requires lock in case another CPU is already
    // running processes)
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[pid]);
        ptable[pid] = p;
        p->ppid_ = 1;
        ptable[1]->children_.push_back(p);
    }

    // add to run queue
    cpus[pid % ncpu].enqueue(p);
}


// proc::exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the current CPU stack, then jumping to kernel assembly code (in
//    k-exception.S). That code transfers the state to the current kernel
//    task's stack, then calls proc::exception().

void proc::exception(regstate* regs) {
    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    //log_printf("proc %d: exception %d @%p\n", id_, regs->reg_intno, regs->reg_rip);

    // Record most recent user-mode %rip.
    if ((regs->reg_cs & 3) != 0) {
        recent_user_rip_ = regs->reg_rip;
    }

    // Show the current cursor location.
    consolestate::get().cursor();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER: {
        cpustate* cpu = this_cpu();
        if (cpu->cpuindex_ == 0) {
            tick();

            // notify the timing wheel
            if (!timing_wheel[ticks % TIMERQS].q_.empty()) {
                timing_wheel[ticks % TIMERQS].wake_all();
            }
        }
        lapicstate::get().ack();
        regs_ = regs;
        yield_noreturn();
        break;                  /* will not be reached */
    }

    case INT_PF: {              // pagefault exception
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if ((regs->reg_cs & 3) == 0) {
            panic_at(regs->reg_rsp, regs->reg_rbp, regs->reg_rip,
                     "Kernel page fault for %p (%s %s)!\n",
                     addr, operation, problem);
        }

        error_printf(CPOS(24, 0), 0x0C00,
                     "Process %d page fault for %p (%s %s, rip=%p)!\n",
                     id_, addr, operation, problem, regs->reg_rip);
        pstate_ = proc::ps_broken;
        yield();
        break;
    }

    case INT_IRQ + IRQ_KEYBOARD:
        keyboardstate::get().handle_interrupt();
        break;

    default:
        if (sata_disk && regs->reg_intno == INT_IRQ + sata_disk->irq_) {
            sata_disk->handle_interrupt();
        } else {
            panic_at(regs->reg_rsp, regs->reg_rbp, regs->reg_rip,
                     "Unexpected exception %d!\n", regs->reg_intno);
        }
        break;                  /* will not be reached */

    }

    // return to interrupted context
}


int stackoverflow() {
    // fill a few pages of junk in the stack
    char overflow[4*PAGESIZE];
    memset(overflow, 0xFF, sizeof(overflow));
    return overflow[sizeof(overflow)/sizeof(overflow[0]) - 1];
}


// process_reap(p)
//    Clean up a zombie.

int process_reap(proc* p) {
    spinlock_guard guard(ptable_lock);

    // remove from parent
    ptable[p->ppid_]->children_.erase(p);

    // reparent children
    while (!p->children_.empty()) {
        proc* child = p->children_.pop_front();
        child->ppid_ = 1;
        ptable[1]->children_.push_back(child);
    }

    int status = p->exit_status_;
    kfree(p);
    kfree(p->pagetable_);

    ptable[p->id_] = nullptr;
    return status;
}


// process_exit(process, regs)
//    Exit the given process with status code `status`.

int process_exit(proc* p, int status) {
    {
        spinlock_guard guard(ptable_lock);

        // free virtual memory
        for (vmiter it(p); it.va() < MEMSIZE_VIRTUAL; it.next()) {
            if (it.perm(PTE_PWU) && it.pa() != ktext2pa(console)) {
                it.kfree_page();
            }
        }

        // switch CPU to safe pagetable before making the current one invalid
        set_pagetable(early_pagetable);
        // free pagetable
        for (ptiter it(p); it.low(); it.next()) {
            it.kfree_ptp();
        }
        // root `pagetable_` pointer cleaned up at a safe time by reaper

        // schedule to be cleaned up at the right time by reaper
        p->pstate_ = proc::ps_broken;
        log_printf("AQAAAAAAAAAAAAAAAAAAAAA %d\n", p->id_);

        // wake up the parent
        proc* parent = ptable[p->ppid_];
        if (parent && parent->pstate_ == proc::ps_blocked) {
            parent->interrupted_ = true;
            parent->wake();
        }
    }

    // don't need `ptable_lock` for the wait queue
    // waitpidq.wake_all();

    process_reap(p);

    return status;
}


// proc::syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value from `proc::syscall()` is returned to the user
//    process in `%rax`.

uintptr_t proc::syscall(regstate* regs) {
    //log_printf("proc %d: syscall %ld @%p\n", id_, regs->reg_rax, regs->reg_rip);

    // Record most recent user-mode %rip.
    recent_user_rip_ = regs->reg_rip;

    uintptr_t result = 0;
    switch (regs->reg_rax) {

    case SYSCALL_KDISPLAY:
        if (kdisplay != (int) regs->reg_rdi) {
            console_clear();
        }
        kdisplay = regs->reg_rdi;
        break;

    case SYSCALL_PANIC:
        panic_at(0, 0, 0, "process %d called sys_panic()", id_);
        break;                  // will not be reached

    case SYSCALL_GETPID:
        result = id_;
        break;

    case SYSCALL_GETPPID:
        result = ppid_;
        break;

    case SYSCALL_YIELD:
        yield();
        break;

    case SYSCALL_WAITPID: {
        int status;
        pid_t pid = waitpid(regs->reg_rdi, &status, regs->reg_rsi);
        result = pid | (((long) status) << 32);
        break;        
    }

    case SYSCALL_PAGE_ALLOC: {
        uintptr_t addr = regs->reg_rdi;
        if (addr >= VA_LOWEND || addr & 0xFFF) {
            return -1;
        }
        void* pg = kalloc(PAGESIZE);
        if (!pg || vmiter(this, addr).try_map(ka2pa(pg), PTE_PWU) < 0) {
            return -1;
        }
        break;
    }

    case SYSCALL_PAUSE: {
        sti();
        for (uintptr_t delay = 0; delay < 1000000; ++delay) {
            pause();
        }
        break;
    }

    case SYSCALL_MSLEEP: {
        const unsigned long until = ticks + (regs->reg_rdi + 9)/10; // round up
        interrupted_ = false;
        waiter w;
        w.p_ = this;
        w.block_until(timing_wheel[until % TIMERQS], [&, until]() -> bool {
            return until <= ticks || interrupted_;
        });
        if (interrupted_) {
            result = E_INTR;
        }
        break;
    }

    case SYSCALL_EXIT:
        process_exit(this, regs->reg_rdi);
        yield_noreturn();
        break;

    case SYSCALL_FORK:
        result = syscall_fork(regs);
        break;

    case SYSCALL_READ:
        result = syscall_read(regs);
        break;

    case SYSCALL_WRITE:
        result = syscall_write(regs);
        break;

    case SYSCALL_READDISKFILE:
        result = syscall_readdiskfile(regs);
        break;

    case SYSCALL_SYNC: {
        int drop = regs->reg_rdi;
        // `drop > 1` asserts that no data blocks are referenced (except
        // possibly superblock and FBB blocks). This can only be ensured on
        // tests that run as the first process.
        if (drop > 1 && strncmp(CHICKADEE_FIRST_PROCESS, "test", 4) != 0) {
            drop = 1;
        }
        result = bufcache::get().sync(drop);
        break;
    }

    case SYSCALL_MAP_CONSOLE: {
        uintptr_t addr = regs->reg_rdi;
        if (addr & 0xFFF || addr > VA_LOWMAX) {
            // `addr` not page-aligned or not in low canonical memory
            return E_INVAL;
        }
        // map the console at `addr`
        result = vmiter(this, addr).try_map(ktext2pa(console), PTE_PWU);
        break;
    }

    case SYSCALL_STACKOVERFLOW:
        result = stackoverflow();
        break;

    case SYSCALL_TESTKALLOC:
        result = test_kalloc();
        break;

    default:
        // no such system call
        log_printf("%d: no such system call %u\n", id_, regs->reg_rax);
        result = E_NOSYS;
        break;

    }

    // before system calls return, check that canaries have not been trampled in either this process descriptor or the CPU states
    assert(canary_ == canary);
    for (int i = 0; i < ncpu; i++) {
        assert(cpus[i].canary_ == canary);
    }

    return result;
}


pid_t proc::waitpid(pid_t pid, int* status, int options) {
    // ensure valid process ID
    assert(pid >= 0 && pid < NPROC);

    pid_t parent = 0;
    {
        spinlock_guard guard(ptable_lock);
        if (ptable[pid]) {
            parent = ptable[pid]->ppid_;
        }
    }

    if ((!pid && children_.empty()) || (pid && id_ != parent)) {
        // either we are not the parent or do not have children
        return E_CHILD;
    }

    proc* zombie = nullptr;
    {
        waiter w;
        w.p_ = this;
        spinlock_guard guard(ptable_lock);
        proc* child = nullptr;
        w.block_until(waitpidq, [&, pid, options, child]() mutable -> bool {
            if (pid) {
                if (ptable[pid]->pstate_ == ps_broken) {
                    zombie = child;
                }
            } else {
                // wait for any child
                for (child = children_.front(); child; child = children_.next(child)) {
                    log_printf("CCCCCCCCCCCCCC %d\n", child->id_);
                    if (child->pstate_ == ps_broken) {
                        zombie = child;
                        break;
                    }
                }
            }

            return zombie || options & W_NOHANG;
        }, guard);
    }
    assert(options & W_NOHANG || zombie->pstate_ == ps_broken);

    if (!zombie && options & W_NOHANG) {
        return E_AGAIN;
    }

    int exit_status = process_reap(zombie);
    if (status) {
        *status = exit_status;
    }

    return zombie->id_;
}


// proc::syscall_fork(regs)
//    Handle fork system call.

int proc::syscall_fork(regstate* regs) {
    pid_t newpid = 0;
    proc* newproc = nullptr;
    {
        // lock the process table for the duration of this block
        spinlock_guard guard(ptable_lock);
        // allocate first open pid
        for (pid_t i = 1; i < NPROC; i++) {
            // blank process descriptors are from processes that never initialized and can be replaced
            if (!ptable[i] || ptable[i]->pstate_ == ps_blank) {
                newpid = i;
                break;
            }
        }
        if (!newpid) {
            // out of PIDs
            return E_MFILE;
        }

        // allocate blank process descriptor and store in table
        newproc = ptable[newpid] = knew<proc>();
        if (!newproc) {
            return E_NOMEM;
        }
        // rest of function is working on the process itself, so can let go of ptable lock now
        newproc->pstate_ = ps_broken;
        newproc->ppid_ = id_;
        children_.push_back(newproc);
    }

    // allocate pagetable
    x86_64_pagetable* newpagetable = newproc->pagetable_ = kalloc_pagetable();
    if (!newpagetable) {
        spinlock_guard guard(ptable_lock);
        ptable[newpid] = nullptr;
        kfree(newproc);
        return E_NOMEM;
    }

    // initialize userspace process
    newproc->init_user(newpid, newpagetable);
    // initialize new process' registers to copy of old process' registers
    *newproc->regs_ = *regs;
    // new process gets 0 as return value
    newproc->regs_->reg_rax = 0;

    // map copies of parent's user-accessible memory into new process' page table
    for (vmiter parent(this); parent.low(); ) {
        if (parent.user()) {
            uintptr_t pa;
            void* newpage = nullptr;
            if (parent.writable() && parent.pa() != ktext2pa(console)) {
                newpage = kalloc(PAGESIZE);
                if (!newpage) {
                    process_exit(newproc, E_NOMEM);
                    return E_NOMEM;
                }
                memcpy(newpage, reinterpret_cast<void*>(pa2ka(parent.pa())), PAGESIZE);
                pa = ka2pa(newpage);
            } else {
                // read-only pages can be shared
                pa = parent.pa();
            }
            if (vmiter(newpagetable, parent.va()).try_map(pa, parent.perm())) {
                kfree(newpage);
                process_exit(newproc, E_NOMEM);
                return E_NOMEM;
            }
            parent.next();
        } else {
            parent.next_range();
        }
    }

    // enqueue on some CPU's run queue
    cpus[newpid % ncpu].enqueue(newproc);

    // parent process gets new process' PID as return value
    return newpid;
}


// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

uintptr_t proc::syscall_read(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.
    auto& kbd = keyboardstate::get();
    auto irqs = kbd.lock_.lock();

    // mark that we are now reading from the keyboard
    // (so `q` should not power off)
    if (kbd.state_ == kbd.boot) {
        kbd.state_ = kbd.input;
    }

    // yield until a line is available
    // (special case: do not block if the user wants to read 0 bytes)
    while (sz != 0 && kbd.eol_ == 0) {
        kbd.lock_.unlock(irqs);
        yield();
        irqs = kbd.lock_.lock();
    }

    // read that line or lines
    size_t n = 0;
    while (kbd.eol_ != 0 && n < sz) {
        if (kbd.buf_[kbd.pos_] == 0x04) {
            // Ctrl-D means EOF
            if (n == 0) {
                kbd.consume(1);
            }
            break;
        } else {
            *reinterpret_cast<char*>(addr) = kbd.buf_[kbd.pos_];
            ++addr;
            ++n;
            kbd.consume(1);
        }
    }

    kbd.lock_.unlock(irqs);
    return n;
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Write to open file `fd` (reg_rdi), rather than `consolestate`.
    // * Validate the write buffer.
    auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    size_t n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(addr);
        ++addr;
        ++n;
        console_printf(0x0F00, "%c", ch);
    }
    return n;
}

uintptr_t proc::syscall_readdiskfile(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    const char* filename = reinterpret_cast<const char*>(regs->reg_rdi);
    unsigned char* buf = reinterpret_cast<unsigned char*>(regs->reg_rsi);
    size_t sz = regs->reg_rdx;
    off_t off = regs->reg_r10;

    if (!sata_disk) {
        return E_IO;
    }

    // read root directory to find file inode number
    auto ino = chkfsstate::get().lookup_inode(filename);
    if (!ino) {
        return E_NOENT;
    }

    // read file inode
    ino->lock_read();
    chkfs_fileiter it(ino);

    size_t nread = 0;
    while (nread < sz) {
        // copy data from current block
        if (bcentry* e = it.find(off).get_disk_entry()) {
            unsigned b = it.block_relative_offset();
            size_t ncopy = min(
                size_t(ino->size - it.offset()),   // bytes left in file
                chkfs::blocksize - b,              // bytes left in block
                sz - nread                         // bytes left in request
            );
            memcpy(buf + nread, e->buf_ + b, ncopy);
            e->put();

            nread += ncopy;
            off += ncopy;
            if (ncopy == 0) {
                break;
            }
        } else {
            break;
        }
    }

    ino->unlock_read();
    ino->put();
    return nread;
}

// proc::syscall(regs)
//    Unblock this process and schedule it on its home CPU.

void proc::wake() {
    pstate_ = ps_runnable;
    cpus[home_cpu_].enqueue(this);
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

static void memshow() {
    static unsigned long last_redisplay = 0;
    static unsigned long last_switch = 0;
    static int showing = 1;

    // redisplay every 0.04 sec
    if (last_redisplay != 0 && ticks - last_redisplay < HZ / 25) {
        return;
    }
    last_redisplay = ticks;

    // switch to a new process every 0.5 sec
    if (ticks - last_switch >= HZ / 2) {
        showing = (showing + 1) % NPROC;
        last_switch = ticks;
    }

    spinlock_guard guard(ptable_lock);

    int search = 0;
    while ((!ptable[showing]
            || !ptable[showing]->pagetable_
            || ptable[showing]->pagetable_ == early_pagetable)
           && search < NPROC) {
        showing = (showing + 1) % NPROC;
        ++search;
    }

    console_memviewer(ptable[showing]);
    if (!ptable[showing]) {
        console_printf(CPOS(10, 29), 0x0F00, "VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}


// tick()
//    Called once every tick (0.01 sec, 1/HZ) by CPU 0. Updates the `ticks`
//    counter and performs other periodic maintenance tasks.

void tick() {
    // Update current time
    ++ticks;

    // Update memviewer display
    if (kdisplay.load(std::memory_order_relaxed) == KDISPLAY_MEMVIEWER) {
        memshow();
    }
}
