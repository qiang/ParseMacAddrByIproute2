//
// Created by liuqiang on 2021/11/18.
//


#include "include/bionic_time_conversions.h"


void monotonic_time_from_realtime_time(timespec& monotonic_time, const timespec& realtime_time) {
    monotonic_time = realtime_time;

    timespec cur_monotonic_time;
    clock_gettime(CLOCK_MONOTONIC, &cur_monotonic_time);
    timespec cur_realtime_time;
    clock_gettime(CLOCK_REALTIME, &cur_realtime_time);

    monotonic_time.tv_nsec -= cur_realtime_time.tv_nsec;
    monotonic_time.tv_nsec += cur_monotonic_time.tv_nsec;
    if (monotonic_time.tv_nsec >= NS_PER_S) {
        monotonic_time.tv_nsec -= NS_PER_S;
        monotonic_time.tv_sec += 1;
    } else if (monotonic_time.tv_nsec < 0) {
        monotonic_time.tv_nsec += NS_PER_S;
        monotonic_time.tv_sec -= 1;
    }
    monotonic_time.tv_sec -= cur_realtime_time.tv_sec;
    monotonic_time.tv_sec += cur_monotonic_time.tv_sec;
}