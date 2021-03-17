CS 161 Problem Set 3 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset3collab.md`.

Answers to written questions
----------------------------

### Changes since the VFS design doc

The interface described in `pset3vfs.md` needed to be split into `file.hh`, which contains the core `file` and `vnode` definitions, and `vnodes.hh`, which contains `vnode` subclasses, because some `vnode` subclasses (specifically `memfile`) depend on headers that depend on `kernel.hh`. However, `file.hh` is used by `kernel.hh`, so keeping these subclasses in `file.hh` would have created a circular header dependency. In the end, this was a beneficial change because now `file.hh` contains the core with minimal dependencies, and additional `vnode` implementations can continue to be added to `vnode.hh` without worrying about interfering with much of the system. Now, `vnode.hh` should only be referenced by `.cc` files that deal with low-level details of the `vnodes` -- all others don’t need to care about anything other than the `read` and `write` methods of the overall `vnode` interface.

Grading notes
-------------
