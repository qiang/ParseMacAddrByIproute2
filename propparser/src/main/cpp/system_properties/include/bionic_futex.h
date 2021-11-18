//
// Created by liuqiang on 2021/11/18.
//

#ifndef _BIONIC_FUTEX_H
#define _BIONIC_FUTEX_H

#include <errno.h>
#include <linux/futex.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <unistd.h>

struct timespec;

static inline __always_inline int __futex(volatile void* ftx, int op, int value,
                                          const timespec* timeout, int bitset) {
    // Our generated syscall assembler sets errno, but our callers (pthread functions) don't want to.
    int saved_errno = errno;
    int result = syscall(__NR_futex, ftx, op, value, timeout, NULL, bitset);
    if (__predict_false(result == -1)) {
        result = -errno;
        errno = saved_errno;
    }
    return result;
}

static inline int __futex_wake(volatile void* ftx, int count) {
    return __futex(ftx, FUTEX_WAKE, count, nullptr, 0);
}

static inline int __futex_wake_ex(volatile void* ftx, bool shared, int count) {
    return __futex(ftx, shared ? FUTEX_WAKE : FUTEX_WAKE_PRIVATE, count, nullptr, 0);
}

static inline int __futex_wait(volatile void* ftx, int value, const timespec* timeout) {
    return __futex(ftx, FUTEX_WAIT, value, timeout, 0);
}

static inline int __futex_wait_ex(volatile void* ftx, bool shared, int value) {
    return __futex(ftx, (shared ? FUTEX_WAIT_BITSET : FUTEX_WAIT_BITSET_PRIVATE), value, nullptr,
                   FUTEX_BITSET_MATCH_ANY);
}

__LIBC_HIDDEN__ int __futex_wait_ex(volatile void* ftx, bool shared, int value,
                                    bool use_realtime_clock, const timespec* abs_timeout);

static inline int __futex_pi_unlock(volatile void* ftx, bool shared) {
    return __futex(ftx, shared ? FUTEX_UNLOCK_PI : FUTEX_UNLOCK_PI_PRIVATE, 0, nullptr, 0);
}

__LIBC_HIDDEN__ int __futex_pi_lock_ex(volatile void* ftx, bool shared, bool use_realtime_clock,
                                       const timespec* abs_timeout);

#endif /* _BIONIC_FUTEX_H */
