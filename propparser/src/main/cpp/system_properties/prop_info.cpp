#include "./include/prop_info.h"

#include <string.h>

constexpr static const char kLongLegacyError[] =
        "Must use __system_property_read_callback() to read";
static_assert(sizeof(kLongLegacyError) < prop_info::kLongLegacyErrorBufferSize,
              "Error message for long properties read by legacy libc must fit within 56 chars");

prop_info::prop_info(const char* name, uint32_t namelen, const char* value, uint32_t valuelen) {
    memcpy(this->name, name, namelen);
    this->name[namelen] = '\0';
    atomic_init(&this->serial, valuelen << 24);
    memcpy(this->value, value, valuelen);
    this->value[valuelen] = '\0';
}

prop_info::prop_info(const char* name, uint32_t namelen, uint32_t long_offset) {
    memcpy(this->name, name, namelen);
    this->name[namelen] = '\0';

    auto error_value_len = sizeof(kLongLegacyError) - 1;
    atomic_init(&this->serial, error_value_len << 24 | kLongFlag);
    memcpy(this->long_property.error_message, kLongLegacyError, sizeof(kLongLegacyError));

    this->long_property.offset = long_offset;
}
