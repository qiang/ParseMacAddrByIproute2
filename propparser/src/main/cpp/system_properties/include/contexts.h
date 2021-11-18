#ifndef ANDROID10DEVICEFINGERPRINT_SYSTEM_CONTEXT_H
#define ANDROID10DEVICEFINGERPRINT_SYSTEM_CONTEXT_H

#include "prop_area.h"
#include "prop_info.h"

class Contexts {
public:
    virtual ~Contexts() {
    }

    virtual bool Initialize(bool writable, const char* filename, bool* fsetxattr_failed) = 0;
    virtual prop_area* GetPropAreaForName(const char* name) = 0;
    virtual prop_area* GetSerialPropArea() = 0;
    virtual void ForEach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) = 0;
    virtual void ResetAccess() = 0;
    virtual void FreeAndUnmap() = 0;
};

#endif