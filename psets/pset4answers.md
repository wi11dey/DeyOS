CS 161 Problem Set 4 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset4collab.md`.

Answers to written questions
----------------------------
### Prefetching
When `syscall_open` is called, the first data block of the opened inode
is prefetched, the reasoning being that a very common action after opening
a diskfile is reading or writing to it from the beginning, like for `cat`
or calculating checksums. The only exception would be when some offset
in the file is already known and `lseek`d to, which is assumed to be the
less common use case. Similarly, when `syscall_read` and `syscall_write`
are called, the next data block _after_ the desired one is prefetched,
with the reasoning being that prefetching in this manner will speed up
any sequential read of a file, and therefore any scanning or checksumming
operations would benefit from this prefetching policy.

### Eviction
The eviction mechanism is only activated if there are no empty slots remaining.
It will first try to find a clean slot with a refcount of zero, which would
be easiest to evict. Ties between clean slots are broken by the LRU policy,
where the LRU clean block will be chosen for eviction earlier than more
recently used ones. When none of the slots are clean with a refcount of
zero, only the LRU dirty block will synced to disk and then evicted from
the cache.

### Optional
 - `sys_unlink` has been implemented, and `make cleanfs run-testwritefs4 fsck` passes. A `p-testunlink.cc` program has also been added for good measure.
 - `sys_rename` has been implemented, and a `p-testrename.cc` testing program has been added, which passes.

Grading notes
-------------
