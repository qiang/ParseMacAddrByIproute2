//
// Created by liuqiang on 2021/11/18.
//

#ifndef ANDROID10DEVICEFINGERPRINT_CONTEXTS_SERIALIZED_H
#define ANDROID10DEVICEFINGERPRINT_CONTEXTS_SERIALIZED_H
#pragma once

#include "../../property_service/include/property_info_parser.h"

#include "stdint.h"

#include "context_node.h"
#include "contexts.h"

class ContextsSerialized : public Contexts {
public:
    virtual ~ContextsSerialized() override {
    }

    virtual bool Initialize(bool writable, const char* filename, bool* fsetxattr_failed) override;
    virtual prop_area* GetPropAreaForName(const char* name) override;
    virtual prop_area* GetSerialPropArea() override {
        return serial_prop_area_;
    }
    virtual void ForEach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) override;
    virtual void ResetAccess() override;
    virtual void FreeAndUnmap() override;

private:
    bool InitializeContextNodes();
    bool InitializeProperties();
    bool MapSerialPropertyArea(bool access_rw, bool* fsetxattr_failed);

    const char* filename_;
    android::properties::PropertyInfoAreaFile property_info_area_file_;
    ContextNode* context_nodes_ = nullptr;
    size_t num_context_nodes_ = 0;
    size_t context_nodes_mmap_size_ = 0;
    prop_area* serial_prop_area_ = nullptr;
};

#endif //ANDROID10DEVICEFINGERPRINT_CONTEXTS_SERIALIZED_H
