#ifndef CHICKADEE_VNODES_H
#define CHICKADEE_VNODES_H
#include "file.hh"
#include "k-devices.hh"


class keyboardnode : public vnode {
public:
    size_t read(char* addr, size_t sz);
    size_t write(const char* addr, size_t sz);
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
    size_t write(const char* addr, size_t sz);

    pipenode() = default;
};


class seekable : public vnode {
public:
    off_t offset_ = 0;
};


class memnode : public seekable {
public:
    memfile& memfile_;

    size_t read(char* addr, size_t sz);
    size_t write(const char* addr, size_t sz);

    memnode(memfile& memfile): memfile_(memfile) {
    }
};


class disknode : public seekable {
public:
    chkfs::inode* inode_;

    size_t read(char* addr, size_t sz);
    size_t write(const char* addr, size_t sz);

    disknode(chkfs::inode* inode): inode_(inode) {
    }
};

#endif
