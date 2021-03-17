#ifndef CHICKADEE_VNODES_H
#define CHICKADEE_VNODES_H
#include "file.hh"
#include "k-devices.hh"


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

#endif
