//
// Created by liuqiang on 2021/11/18.
//

#ifndef ANDROID10DEVICEFINGERPRINT_CONTEXTS_SPLIT_H
#define ANDROID10DEVICEFINGERPRINT_CONTEXTS_SPLIT_H
#pragma once

#include "contexts.h"

struct PrefixNode;
class ContextListNode;

class ContextsSplit : public Contexts {
public:
    virtual ~ContextsSplit() override {
    }

    virtual bool Initialize(bool writable, const char* filename, bool* fsetxattr_failed) override;
    virtual prop_area* GetPropAreaForName(const char* name) override;
    virtual prop_area* GetSerialPropArea() override {
        return serial_prop_area_;
    }
    virtual void ForEach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) override;
    virtual void ResetAccess() override;
    virtual void FreeAndUnmap() override;

    PrefixNode* GetPrefixNodeForName(const char* name);

protected:
    bool MapSerialPropertyArea(bool access_rw, bool* fsetxattr_failed);
    bool InitializePropertiesFromFile(const char* filename);
    bool InitializeProperties();

    PrefixNode* prefixes_ = nullptr;
    ContextListNode* contexts_ = nullptr;
    prop_area* serial_prop_area_ = nullptr;
    const char* filename_ = nullptr;
};

#endif //ANDROID10DEVICEFINGERPRINT_CONTEXTS_SPLIT_H
