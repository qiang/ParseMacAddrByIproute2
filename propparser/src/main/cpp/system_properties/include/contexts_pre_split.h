//
// Created by liuqiang on 2021/11/18.
//

#ifndef ANDROID10DEVICEFINGERPRINT_CONTEXTS_PRE_SPLIT_H
#define ANDROID10DEVICEFINGERPRINT_CONTEXTS_PRE_SPLIT_H
#pragma once

#include "contexts.h"
#include "prop_area.h"
#include "prop_info.h"

class ContextsPreSplit : public Contexts {
public:
    virtual ~ContextsPreSplit() override {
    }

    // We'll never initialize this legacy option as writable, so don't even check the arg.
    virtual bool Initialize(bool, const char* filename, bool*) override {
        pre_split_prop_area_ = prop_area::map_prop_area(filename);
        return pre_split_prop_area_ != nullptr;
    }

    virtual prop_area* GetPropAreaForName(const char*) override {
        return pre_split_prop_area_;
    }

    virtual prop_area* GetSerialPropArea() override {
        return pre_split_prop_area_;
    }

    virtual void ForEach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) override {
        pre_split_prop_area_->foreach (propfn, cookie);
    }

    // This is a no-op for pre-split properties as there is only one property file and it is
    // accessible by all domains
    virtual void ResetAccess() override {
    }

    virtual void FreeAndUnmap() override {
        prop_area::unmap_prop_area(&pre_split_prop_area_);
    }

private:
    prop_area* pre_split_prop_area_ = nullptr;
};

#endif //ANDROID10DEVICEFINGERPRINT_CONTEXTS_PRE_SPLIT_H
