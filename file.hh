#ifndef CHICKADEE_FILE_H
#define CHICKADEE_FILE_H
#include "chickadeefs.hh"

#define PIPE_SIZE 512


class vnode {
public:
    virtual size_t read(char* addr, size_t sz) = 0;
    virtual size_t write(const char* addr, size_t sz) = 0;
};


struct file {
    enum ftype_t { ft_keyboard, ft_pipe, ft_memfile, ft_diskfile } ftype_;
    int perm_;
    vnode* vnode_;

    int ref_ = 0;
    spinlock lock_;

    file(ftype_t ftype, int perm, vnode* vnode): ftype_(ftype), perm_(perm), vnode_(vnode) {
    }
};

#endif

