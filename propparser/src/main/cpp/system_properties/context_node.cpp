//
// Created by liuqiang on 2021/11/18.
//

#include "include/context_node.h"

//#include <limits.h>
#include <unistd.h>
#include <safe_log.h>

//#include <async_safe/log.h>

#include "include/system_properties.h"

// pthread_mutex_lock() calls into system_properties in the case of contention.
// This creates a risk of dead lock if any system_properties functions
// use pthread locks after system_property initialization.
//
// For this reason, the below three functions use a bionic Lock and static
// allocation of memory for each filename.

bool ContextNode::Open(bool access_rw, bool *fsetxattr_failed) {
//    lock_.lock();
//    if (pa_) {
//        lock_.unlock();
//        return true;
//    }
    if (pa_) {
        return true;
    }

    char filename[PROP_FILENAME_MAX];
    int len = async_safe_format_buffer(filename, sizeof(filename), "%s/%s", filename_, context_);
    if (len < 0 || len >= PROP_FILENAME_MAX) {
//        lock_.unlock();
        return false;
    }

    if (access_rw) {
        pa_ = prop_area::map_prop_area_rw(filename, context_, fsetxattr_failed);
    } else {
        pa_ = prop_area::map_prop_area(filename);
    }
//    lock_.unlock();
    return pa_;
}

bool ContextNode::CheckAccessAndOpen() {
    if (!pa_ && !no_access_) {
        if (!CheckAccess() || !Open(false, nullptr)) {
            no_access_ = true;
        }
    }
    return pa_;
}

void ContextNode::ResetAccess() {
    if (!CheckAccess()) {
        Unmap();
        no_access_ = true;
    } else {
        no_access_ = false;
    }
}

bool ContextNode::CheckAccess() {
    char filename[PROP_FILENAME_MAX];
    int len = async_safe_format_buffer(filename, sizeof(filename), "%s/%s", filename_, context_);
    if (len < 0 || len >= PROP_FILENAME_MAX) {
        return false;
    }

    return access(filename, R_OK) == 0;
}

void ContextNode::Unmap() {
    prop_area::unmap_prop_area(&pa_);
}
