//
// Created by liuqiang on 2021/11/18.
//

#ifndef _BIONIC_TIME_CONVERSIONS_H
#define _BIONIC_TIME_CONVERSIONS_H

#include <errno.h>
#include <time.h>
#include <sys/cdefs.h>

#include "bionic_constants.h"

void monotonic_time_from_realtime_time(timespec& monotonic_time,
                                       const timespec& realtime_time);

//static inline int check_timespec(const timespec* ts, bool null_allowed) {
//    if (null_allowed && ts == nullptr) {
//        return 0;
//    }
//    // glibc just segfaults if you pass a null timespec.
//    // That seems a lot more likely to catch bad code than returning EINVAL.
//    if (ts->tv_nsec < 0 || ts->tv_nsec >= NS_PER_S) {
//        return EINVAL;
//    }
//    if (ts->tv_sec < 0) {
//        return ETIMEDOUT;
//    }
//    return 0;
//}
//
//#if !defined(__LP64__)
//static inline void absolute_timespec_from_timespec(timespec& abs_ts, const timespec& ts, clockid_t clock) {
//    clock_gettime(clock, &abs_ts);
//    abs_ts.tv_sec += ts.tv_sec;
//    abs_ts.tv_nsec += ts.tv_nsec;
//    if (abs_ts.tv_nsec >= NS_PER_S) {
//        abs_ts.tv_nsec -= NS_PER_S;
//        abs_ts.tv_sec++;
//    }
//}
//#endif

#endif
