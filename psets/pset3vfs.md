CS 161 Problem Set 3 VFS Design Document
========================================

## Interface

```cpp
class vnode {
public:
    virtual size_t read(char* addr, size_t sz) = 0;
    virtual size_t write(char const* addr, size_t sz) = 0;
};


struct file {
    enum ftype_t { ft_keyboard, ft_pipe, ft_memfile } ftype_;
    int perm_;
    vnode* vnode_;

    int ref_ = 0;
    spinlock lock_;

    file(ftype_t ftype, int perm, vnode* vnode): ftype_(ftype), perm_(perm), vnode_(vnode) {
    }
};

class keyboardnode : public vnode {
public:
    size_t read(char* addr, size_t sz);
    size_t write(char const* addr, size_t sz);
};


class pipenode : public vnode {
    char buf_[PIPE_SIZE];
    size_t pos_ = 0;
    size_t len_ = 0;

public:
    spinlock lock_;

    int readers_ = 0;
    int writers_ = 0;

    size_t read(char* addr, size_t sz);
    size_t write(char const* addr, size_t sz);

    pipenode() = default;
};


class memnode : public vnode {
    memfile& memfile_;
    size_t offset_ = 0;

public:
    size_t read(char* addr, size_t sz);
    size_t write(char const* addr, size_t sz);

    memnode(memfile& memfile, size_t offset): memfile_(memfile), offset_(offset) {
    }
};
```

Every object in the VFS is a `file`. Metadata like permissions (`perm_`) and type of file (`ftype_`) are kept track of in the `file`. Each file must have a non-null `vnode_`, which points to an instance of the respective `vnode` subclass which handles the real reading and writing to the underlying real object the `file` represents.

The following invariants must be respected:

 - `vnode_` must never be `nullptr`.
 - A `file` of `ftype_` `ft_keyboard` must have a `vnode_` that is an instance of a `keyboardnode`, or subclass thereof.
 - A `file` of `ftype_` `ft_pipe` must have a `vnode_` that is an instance of a `pipenode`, or subclass thereof.
 - A `file` of `ftype_` `ft_memfile` must have a `vnode_` that is an instance of a `memnode`, or subclass thereof.

A file also keeps track of how many references there are to it, i.e. how many processes have a pointer to in their `ftable_`s.

`vnode`s have considerable freedom in their implementation details, as evidenced by the more involved implementation of `pipenode`. Specifically, they are responsible for keeping track of offsets, and any details specific to their type of file backend only. For example, since pipes have two ends, they additionally keep track of how many readers vs. writers are using the pipe at a given moment.

## Functionality
While each process’ `ftable_` is limited to `NFILES` open file descriptors at any given time (currently 256), I chose to _not_ implement any kind of global file table. Some implications:

 - All files must be dynamically allocated with `knew<file>`.
 - Since `vnode_` must never be null, a `vnode` implementation, also dynamically allocated with `knew<file>`, must be passed into the constructor of a `file` when `knew`ing it.
 - Whenever a `file` is entered into another `ftable_`, its `ref_` count should be incremented.
 - Likewise, whenever a `file` is closed out of a process’ `ftable_`, or a process that had it open exits, the file’s `ref_` count should be decremented.
 - When a `file`’s `ref_` count drops to 0, it must be `kfree`d.
 - However, freedom is given to `vnode` implementations to specify whether or not they should also be `kfree`d with a file or at a different, `vnode`-specified time (see below).
 
Since a `pipenode` can be the `vnode_` for multiple `file`s at a time, they should _not_ be `kfree`d when a file is. Instead, the following invariants hold for the `pipenode` interface:

 - Each `pipenode` knows nothing about the permissions of `file`s that reference it. It is the caller’s responsibility to increment a `pipenode`’s `readers_` count when a file that can read from it is instantiated or gets a new reference.
 - Likewise, a `pipenode`’s `writers_` count should be incremented when a file than can write to it is instantiated or gets a new reference.
 - Whenever those files lose a reference, the appropriate `readers_`/`writers_` variable should be decremented.
 - If `readers_` and `writers_` ever both drop to 0, only then should the `pipenode` be `kfree`’d

`keyboardnode` and `memnode` should each belong to exactly 1 `file` (that may be referenced by multiple processes), and their lifetimes should match exactly with that of the `file`.

To actually read and write from a file, call the `read` and `write` functions of its `vnode_`, which are guaranteed to exist for live files.

 - The first argument of `read` should be a pointer to a buffer of size at least `sz` which will be the destination of the read contents. The return value is the number of bytes actually read.
  - The first argument of `write` should be a pointer to a buffer of size at least `sz` which contains the bytes to be written. The return value is the number of bytes actually written.

One peculiarity is that a `keyboardnode` reads from the keyboard, but writes to the console. It can be used as an effective stdin/stdout.

## Synchronization and blocking

 - Whenever a `file`’s `ref_` count is being changed, its `lock_` should be held.
 - Whenever a `pipenode`’s `readers_`/`writers_` count is being changed, its `lock_` should be held.

Any `vnode`’s `read`/`write` implementation can block. Specifically for `pipenode`:

 - A `pipenode`’s `read` will block until there is data in the pipe if the pipe is empty when it is called.
 - A `pipenode`’s `write` will block until there is space in the pipe if the pipe is full when it is called.
 
## Future directions

I want to eventually make my file system centered around URIs, where permissions will be determined by the Same-Origin Policy like in browsers.

Currently, each `ft_pipe` file is either a reader or writer to a pipe, but the `pipenode` implementation does not enforce this restriction. Eventually, bi-directional pipes may be fully supported where a process can hold a `ft_pipe` file descriptor that can both read and write the same pipe.

## Concerns

I’m excited!
