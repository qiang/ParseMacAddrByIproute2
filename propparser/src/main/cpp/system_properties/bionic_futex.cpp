//
// Created by liuqiang on 2021/11/18.
//

#include "include/bionic_futex.h"

#include <time.h>

#include "include/bionic_time_conversions.h"

static inline __always_inline int FutexWithTimeout(volatile void* ftx, int op, int value,
                                                   bool use_realtime_clock,
                                                   const timespec* abs_timeout, int bitset) {
    const timespec* futex_abs_timeout = abs_timeout;
    // pthread's and semaphore's default behavior is to use CLOCK_REALTIME, however this behavior is
    // essentially never intended, as that clock is prone to change discontinuously.
    //
    // What users really intend is to use CLOCK_MONOTONIC, however only pthread_cond_timedwait()
    // provides this as an option and even there, a large amount of existing code does not opt into
    // CLOCK_MONOTONIC.
    //
    // We have seen numerous bugs directly attributable to this difference.  Therefore, we provide
    // this general workaround to always use CLOCK_MONOTONIC for waiting, regardless of what the input
    // timespec is.
    timespec converted_monotonic_abs_timeout;
    if (abs_timeout && use_realtime_clock) {
        monotonic_time_from_realtime_time(converted_monotonic_abs_timeout, *abs_timeout);
        if (converted_monotonic_abs_timeout.tv_sec < 0) {
            return -ETIMEDOUT;
        }
        futex_abs_timeout = &converted_monotonic_abs_timeout;
    }

    return __futex(ftx, op, value, futex_abs_timeout, bitset);
}



int __futex_wait_ex(volatile void* ftx, bool shared, int value, bool use_realtime_clock,
                    const timespec* abs_timeout) {
    return FutexWithTimeout(ftx, (shared ? FUTEX_WAIT_BITSET : FUTEX_WAIT_BITSET_PRIVATE), value,
                            use_realtime_clock, abs_timeout, FUTEX_BITSET_MATCH_ANY);
}

int __futex_pi_lock_ex(volatile void* ftx, bool shared, bool use_realtime_clock,
                       const timespec* abs_timeout) {
    return FutexWithTimeout(ftx, (shared ? FUTEX_LOCK_PI : FUTEX_LOCK_PI_PRIVATE), 0,
                            use_realtime_clock, abs_timeout, 0);
}
