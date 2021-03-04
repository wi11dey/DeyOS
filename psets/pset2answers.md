CS 161 Problem Set 2 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset2collab.md`.

Answers to written questions
----------------------------
### Part A
Done.

The final freeing is done in Part D by the reaper, so all the cleanup code is at one point. I ensured that the memviewer and process exiting is properly synchronized by holding the existing ptable_lock while freeing page tables to keep lock scheme complexity low.

### Part B
Done.

### Part C
I chose to use a per-process linked-list to store each process’ children because of the O(1) insert and delete operations, as well as the existing well-tested implementation in `k-list.cc`. Reparenting a process’ children therefore takes only O(C) time, where C is the number of children a process has, since only the dying process’ `children_` iterated during reparenting, which is a linear-time operation for linked-lists.

Since it became obvious very quickly that most operations which require editing children and parents will also need to touch the process table at some points, I abandoned by initial separate process hierarchy lock and opted to use `ptable_lock` to protect these synchronization invariants:
 - A process’ `children_` should only be edited when the `ptable_lock` is held.
 - Similarly, a process’ parent in `ppid_` should only be edited when the `ptable_lock` is held.

### Part D
`waitpid()` uses the same invariants as above when dealing with `ptable` and `ppid_`, with the additional, separate lock on the wait queue when traversing it to clear current waiters, so multiple threads don’t try to traverse at the same time and drop some.

In order to allow `waitpid()` to open up PIDs for reuse when it sees fit, all the finalization code was moved to a shared `process_reap()` that takes care of tying up loose ends.

### Part E
Done.

### Part F
I implemented a timing wheel in `kernel.cc`, which still accurately took care of `sys_msleep`, but needed only around 258 resumes, whereas the singular wait queue for all timing was hitting around 30000 (!)

### Part G
Done.

Grading notes
-------------
