//
// Created by liuqiang on 2021/11/18.
//

#ifndef ANDROID10DEVICEFINGERPRINT_CONTEXT_NODE_H
#define ANDROID10DEVICEFINGERPRINT_CONTEXT_NODE_H
#pragma once

//#include "private/bionic_lock.h"

#include "prop_area.h"

class ContextNode {
public:
    ContextNode(const char* context, const char* filename)
            : context_(context), pa_(nullptr), no_access_(false), filename_(filename) {
//        lock_.init(false);
    }
    ~ContextNode() {
        Unmap();
    }

    BIONIC_DISALLOW_COPY_AND_ASSIGN(ContextNode);

    bool Open(bool access_rw, bool* fsetxattr_failed);
    bool CheckAccessAndOpen();
    void ResetAccess();
    void Unmap();

    const char* context() const {
        return context_;
    }
    prop_area* pa() {
        return pa_;
    }

private:
    bool CheckAccess();

//    Lock lock_;
    const char* context_;
    prop_area* pa_;
    bool no_access_;
    const char* filename_;
};

#endif //ANDROID10DEVICEFINGERPRINT_CONTEXT_NODE_H
