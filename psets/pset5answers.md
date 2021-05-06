CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------
### Synchronization
The file table is now dynamically allocated, rather than being an array
in `struct proc`, so the pointer is copied on thread clones. The lifetime
is tied to that of the process, so is freed during reaping. It is not freed
on `execv` because file descriptors should persist across `execv`s.

Since process operations often involve checking threads, like in the case
of `waitpid`, `ptable_lock` is used to synchronize both `ptable` and `pidtable`.

### Project
I have ported Emacs, one of the oldest and most full-featured development environments, to Chickadee. It has a rich terminal interface, with buttons, widgets, and other GUI elements, and runs many other applications written in Lisp. (It was basically the Atom before Atom.)

1. My goal was to port the terminal interface of Emacs and get it to fully initialize. Explicit non-goals were the graphical interface, dynamic linking capabilities of Emacs, and the networking parts of it.
2. Emacs is built as a Lisp VM on top of a fast C core. I have ported the C core in my fork, following the same structure as the Windows support (w16*.c and w32*.c) files, and the Mac (ns*.c) ports.
3. See my commits for the port at https://github.com/wi11dey/emacs
4. Emacs has been continuously developed since the Cold War, and uses some conventions only known to old Lisp programmers. However, the C core is small and was still able to be ported to Chickadee’s syscall interface, leaving some parts like networking and debugging syscalls as stubs.
5. My fork is included as a submodule of this repo, and needs to live under the `emacs` subdirectory of the root Chickadee source dir for the `p-emacs.cc` glue program to find it. To test, clone this repo with `git clone https://github.com/CS161/cs-161-s21-problem-sets-wi11dey.git` then get the submodule with `git submodule update --init --remote`, then `make run-emacs`. Enjoy an IDE in Chickadee :)

Grading notes
-------------
