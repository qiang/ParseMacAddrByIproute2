#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "macros.h"

#include "prop_info.h"

// Properties are stored in a hybrid trie/binary tree structure.
// Each property's name is delimited at '.' characters, and the tokens are put
// into a trie structure.  Siblings at each level of the trie are stored in a
// binary tree.  For instance, "ro.secure"="1" could be stored as follows:
//
// +-----+   children    +----+   children    +--------+
// |     |-------------->| ro |-------------->| secure |
// +-----+               +----+               +--------+
//                       /    \                /   |
//                 left /      \ right   left /    |  prop   +===========+
//                     v        v            v     +-------->| ro.secure |
//                  +-----+   +-----+     +-----+            +-----------+
//                  | net |   | sys |     | com |            |     1     |
//                  +-----+   +-----+     +-----+            +===========+

// Represents a node in the trie.
struct prop_bt {
    uint32_t namelen;

    // The property trie is updated only by the init process (single threaded) which provides
    // property service. And it can be read by multiple threads at the same time.
    // As the property trie is not protected by locks, we use atomic_uint_least32_t types for the
    // left, right, children "pointers" in the trie node. To make sure readers who see the
    // change of "pointers" can also notice the change of prop_bt structure contents pointed by
    // the "pointers", we always use release-consume ordering pair when accessing these "pointers".

    // prop "points" to prop_info structure if there is a propery associated with the trie node.
    // Its situation is similar to the left, right, children "pointers". So we use
    // atomic_uint_least32_t and release-consume ordering to protect it as well.

    // We should also avoid rereading these fields redundantly, since not
    // all processor implementations ensure that multiple loads from the
    // same field are carried out in the right order.
    atomic_uint_least32_t prop;

    atomic_uint_least32_t left;
    atomic_uint_least32_t right;

    atomic_uint_least32_t children;

    char name[0];

    prop_bt(const char *name, const uint32_t name_length) {
        this->namelen = name_length;
        memcpy(this->name, name, name_length);
        this->name[name_length] = '\0';
    }

private:
    BIONIC_DISALLOW_COPY_AND_ASSIGN(prop_bt);
};

class prop_area {
public:
    static prop_area * map_prop_mem(void *memaddr, size_t size);

    static prop_area *map_prop_area_rw(const char *filename, const char *context,
                                       bool *fsetxattr_failed);

    static prop_area *map_prop_area(const char *filename);

    static void unmap_prop_area(prop_area **pa) {
        if (*pa) {
            munmap(*pa, pa_size_);
            *pa = nullptr;
        }
    }

    prop_area(const uint32_t magic, const uint32_t version) : magic_(magic), version_(version) {
        atomic_init(&serial_, 0u);
        memset(reserved_, 0, sizeof(reserved_));
        // Allocate enough space for the root node.
        bytes_used_ = sizeof(prop_bt);
        // To make property reads wait-free, we reserve a
        // PROP_VALUE_MAX-sized block of memory, the "dirty backup area",
        // just after the root node. When we're about to modify a
        // property, we copy the old value into the dirty backup area and
        // copy the new value into the prop_info structure. Before
        // starting the latter copy, we mark the property's serial as
        // being dirty. If a reader comes along while we're doing the
        // property update and sees a dirty serial, the reader copies from
        // the dirty backup area instead of the property value
        // proper. After the copy, the reader checks whether the property
        // serial is the same: if it is, the dirty backup area hasn't been
        // reused for something else and we can complete the
        // read immediately.
        bytes_used_ += __BIONIC_ALIGN(PROP_VALUE_MAX, sizeof(uint_least32_t));
    }

    const prop_info *find(const char *name);

    bool add(const char *name, unsigned int namelen, const char *value, unsigned int valuelen);

    bool foreach(void (*propfn)(const prop_info *pi, void *cookie), void *cookie);

    atomic_uint_least32_t *serial() {
        return &serial_;
    }

    uint32_t magic() const {
        return magic_;
    }

    uint32_t version() const {
        return version_;
    }

    char *dirty_backup_area() {
        return data_ + sizeof(prop_bt);
    }

private:
    static prop_area *map_fd_ro(const int fd);

    void *allocate_obj(const size_t size, uint_least32_t *const off);

    prop_bt *new_prop_bt(const char *name, uint32_t namelen, uint_least32_t *const off);

    prop_info *
    new_prop_info(const char *name, uint32_t namelen, const char *value, uint32_t valuelen,
                  uint_least32_t *const off);

    void *to_prop_obj(uint_least32_t off);

    prop_bt *to_prop_bt(atomic_uint_least32_t *off_p);

    prop_info *to_prop_info(atomic_uint_least32_t *off_p);

    prop_bt *root_node();

    prop_bt *
    find_prop_bt(prop_bt *const bt, const char *name, uint32_t namelen, bool alloc_if_needed);

    const prop_info *find_property(prop_bt *const trie, const char *name, uint32_t namelen,
                                   const char *value, uint32_t valuelen, bool alloc_if_needed);

    bool foreach_property(prop_bt *const trie, void (*propfn)(const prop_info *pi, void *cookie),
                          void *cookie);

    // The original design doesn't include pa_size or pa_data_size in the prop_area struct itself.
    // Since we'll need to be backwards compatible with that design, we don't gain much by adding it
    // now, especially since we don't have any plans to make different property areas different sizes,
    // and thus we share these two variables among all instances.
    static size_t pa_size_;
    static size_t pa_data_size_;

    uint32_t bytes_used_;
    atomic_uint_least32_t serial_;
    uint32_t magic_;
    uint32_t version_;
    uint32_t reserved_[28];
    char data_[0];

    BIONIC_DISALLOW_COPY_AND_ASSIGN(prop_area);
};
