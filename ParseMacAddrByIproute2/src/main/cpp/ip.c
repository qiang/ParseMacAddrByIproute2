//
// Created by liuqiang on 2021/7/9.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include "SNAPSHOT.h"
#include "utils.h"
#include "ip_common.h"
#include "namespace.h"
#include "color.h"

int preferred_family = AF_UNSPEC;
int human_readable;
int use_iec;
int show_stats;
int show_details;
int oneline;
int brief;
int json;
int timestamp;
const char *_SL_;
int force;
int max_flush_loops = 10;
int batch_mode;
bool do_all;

struct rtnl_handle rth = {.fd = -1};


int main() {

    _SL_ = oneline ? "\\" : "\n";


    if (rtnl_open(&rth, 0) < 0)
        exit(1);

    char *arr[] = {
            "wlan0"
    };

    do_ipaddr(1, arr);

}
