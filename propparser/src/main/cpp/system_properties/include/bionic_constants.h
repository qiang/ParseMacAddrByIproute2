//
// Created by liuqiang on 2021/11/18.
//

#ifndef _BIONIC_CONSTANTS_H_
#define _BIONIC_CONSTANTS_H_

#define NS_PER_S 1000000000

// Size of the shadow call stack. This must be a power of 2.
#define SCS_SIZE (8 * 1024)
#include <errno.h>
#include <time.h>
#include <sys/cdefs.h>
// The shadow call stack is allocated at an aligned address within a guard region of this size. The
// guard region must be large enough that we can allocate an SCS_SIZE-aligned SCS while ensuring
// that there is at least one guard page after the SCS so that a stack overflow results in a SIGSEGV
// instead of corrupting the allocation that comes after it.
#define SCS_GUARD_REGION_SIZE (16 * 1024 * 1024)

#endif // _BIONIC_CONSTANTS_H_