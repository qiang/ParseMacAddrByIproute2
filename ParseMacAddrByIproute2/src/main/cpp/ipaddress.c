//
// Created by liuqiang on 2021/7/9.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <fnmatch.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <linux/net_namespace.h>

#include "utils.h"
#include "rt_names.h"
#include "utils.h"
#include "ll_map.h"
#include "ip_common.h"
#include "xdp.h"
#include "color.h"


enum {
    IPADD_LIST,
    IPADD_FLUSH,
    IPADD_SAVE,
};

static const char *oper_states[] = {
        "UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN",
        "TESTING", "DORMANT", "UP"
};

/* Mapping from argument to address flag mask */
struct {
    const char *name;
    unsigned long value;
} ifa_flag_names[] = {
        {"secondary",      IFA_F_SECONDARY},
        {"temporary",      IFA_F_SECONDARY},
        {"nodad",          IFA_F_NODAD},
        {"optimistic",     IFA_F_OPTIMISTIC},
        {"dadfailed",      IFA_F_DADFAILED},
        {"home",           IFA_F_HOMEADDRESS},
        {"deprecated",     IFA_F_DEPRECATED},
        {"tentative",      IFA_F_TENTATIVE},
        {"permanent",      IFA_F_PERMANENT},
        {"mngtmpaddr",     IFA_F_MANAGETEMPADDR},
        {"noprefixroute",  IFA_F_NOPREFIXROUTE},
        {"autojoin",       IFA_F_MCAUTOJOIN},
        {"stable-privacy", IFA_F_STABLE_PRIVACY},
};


static struct link_filter filter;

static int do_link;

static __u32 ipadd_dump_magic = 0x47361222;


static void usage(void) {

}

void ipaddr_reset_filter(int oneline, int ifindex) {
    memset(&filter, 0, sizeof(filter));
    filter.oneline = oneline;
    filter.ifindex = ifindex;
}

void print_num(FILE *fp, unsigned int width, uint64_t count) {
    const char *prefix = "kMGTPE";
    const unsigned int base = use_iec ? 1024 : 1000;
    uint64_t powi = 1;
    uint16_t powj = 1;
    uint8_t precision = 2;
    char buf[64];

    if (!human_readable || count < base) {
        fprintf(fp, "%-*"PRIu64" ", width, count);
        return;
    }

    /* increase value by a factor of 1000/1024 and print
     * if result is something a human can read
     */
    for (;;) {
        powi *= base;
        if (count / base < powi)
            break;

        if (!prefix[1])
            break;
        ++prefix;
    }

    /* try to guess a good number of digits for precision */
    for (; precision > 0; precision--) {
        powj *= 10;
        if (count / powi < powj)
            break;
    }

    snprintf(buf, sizeof(buf), "%.*f%c%s", precision,
             (double) count / powi, *prefix, use_iec ? "i" : "");

    fprintf(fp, "%-*s ", width, buf);
}

static int ipadd_save_prep(void) {
    int ret;

    if (isatty(STDOUT_FILENO)) {
        fprintf(stderr, "Not sending a binary stream to stdout\n");
        return -1;
    }

    ret = write(STDOUT_FILENO, &ipadd_dump_magic, sizeof(ipadd_dump_magic));
    if (ret != sizeof(ipadd_dump_magic)) {
        fprintf(stderr, "Can't write magic to dump file\n");
        return -1;
    }

    return 0;
}


static int flush_update(void) {
    /*
     * Note that the kernel may delete multiple addresses for one
     * delete request (e.g. if ipv4 address promotion is disabled).
     * Since a flush operation is really a series of delete requests
     * its possible that we may request an address delete that has
     * already been done by the kernel. Therefore, ignore EADDRNOTAVAIL
     * errors returned from a flush request
     */
    if ((rtnl_send_check(&rth, filter.flushb, filter.flushp) < 0) &&
        (errno != EADDRNOTAVAIL)) {
        perror("Failed to send flush request");
        return -1;
    }
    filter.flushp = 0;
    return 0;
}


static int ipaddr_flush(void) {
    int round = 0;
    char flushb[4096 - 512];

    filter.flushb = flushb;
    filter.flushp = 0;
    filter.flushe = sizeof(flushb);

    while ((max_flush_loops == 0) || (round < max_flush_loops)) {
        if (rtnl_wilddump_request(&rth, filter.family, RTM_GETADDR) < 0) {
            perror("Cannot send dump request");
            exit(1);
        }
        filter.flushed = 0;
        if (rtnl_dump_filter_nc(&rth, print_addrinfo,
                                stdout, NLM_F_DUMP_INTR) < 0) {
            fprintf(stderr, "Flush terminated\n");
            exit(1);
        }
        if (filter.flushed == 0) {
            flush_done:
            if (show_stats) {
                if (round == 0)
                    printf("Nothing to flush.\n");
                else
                    printf("*** Flush is complete after %d round%s ***\n", round,
                           round > 1 ? "s" : "");
            }
            fflush(stdout);
            return 0;
        }
        round++;
        if (flush_update() < 0)
            return 1;

        if (show_stats) {
            printf("\n*** Round %d, deleting %d addresses ***\n", round, filter.flushed);
            fflush(stdout);
        }

        /* If we are flushing, and specifying primary, then we
         * want to flush only a single round.  Otherwise, we'll
         * start flushing secondaries that were promoted to
         * primaries.
         */
        if (!(filter.flags & IFA_F_SECONDARY) && (filter.flagmask & IFA_F_SECONDARY))
            goto flush_done;
    }
    fprintf(stderr, "*** Flush remains incomplete after %d rounds. ***\n", max_flush_loops);
    fflush(stderr);
    return 1;
}

static int get_filter(const char *arg) {
    unsigned int i;

    /* Special cases */
    if (strcmp(arg, "dynamic") == 0) {
        filter.flags &= ~IFA_F_PERMANENT;
        filter.flagmask |= IFA_F_PERMANENT;
    } else if (strcmp(arg, "primary") == 0) {
        filter.flags &= ~IFA_F_SECONDARY;
        filter.flagmask |= IFA_F_SECONDARY;
    } else if (*arg == '-') {
        for (i = 0; i < ARRAY_SIZE(ifa_flag_names); i++) {
            if (strcmp(arg + 1, ifa_flag_names[i].name))
                continue;

            filter.flags &= ifa_flag_names[i].value;
            filter.flagmask |= ifa_flag_names[i].value;
            return 0;
        }

        return -1;
    } else {
        for (i = 0; i < ARRAY_SIZE(ifa_flag_names); i++) {
            if (strcmp(arg, ifa_flag_names[i].name))
                continue;
            filter.flags |= ifa_flag_names[i].value;
            filter.flagmask |= ifa_flag_names[i].value;
            return 0;
        }
        return -1;
    }

    return 0;
}

static int save_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n,
                      void *arg) {
    int ret;

    ret = write(STDOUT_FILENO, n, n->nlmsg_len);
    if ((ret > 0) && (ret != n->nlmsg_len)) {
        fprintf(stderr, "Short write while saving nlmsg\n");
        ret = -EIO;
    }

    return ret == n->nlmsg_len ? 0 : ret;
}

static int iplink_filter_req(struct nlmsghdr *nlh, int reqlen) {
    int err;

    err = addattr32(nlh, reqlen, IFLA_EXT_MASK, RTEXT_FILTER_VF);
    if (err)
        return err;

    if (filter.master) {
        err = addattr32(nlh, reqlen, IFLA_MASTER, filter.master);
        if (err)
            return err;
    }

    if (filter.kind) {
        struct rtattr *linkinfo;

        linkinfo = addattr_nest(nlh, reqlen, IFLA_LINKINFO);

        err = addattr_l(nlh, reqlen, IFLA_INFO_KIND, filter.kind,
                        strlen(filter.kind));
        if (err)
            return err;

        addattr_nest_end(nlh, linkinfo);
    }

    return 0;
}

static unsigned int get_ifa_flags(struct ifaddrmsg *ifa,
                                  struct rtattr *ifa_flags_attr) {
    return ifa_flags_attr ? rta_getattr_u32(ifa_flags_attr) :
           ifa->ifa_flags;
}

static void ipaddr_filter(struct nlmsg_chain *linfo, struct nlmsg_chain *ainfo) {
    struct nlmsg_list *l, **lp;

    lp = &linfo->head;
    while ((l = *lp) != NULL) {
        int ok = 0;
        int missing_net_address = 1;
        struct ifinfomsg *ifi = NLMSG_DATA(&l->h);
        struct nlmsg_list *a;

        for (a = ainfo->head; a; a = a->next) {
            struct nlmsghdr *n = &a->h;
            struct ifaddrmsg *ifa = NLMSG_DATA(n);
            struct rtattr *tb[IFA_MAX + 1];
            unsigned int ifa_flags;

            if (ifa->ifa_index != ifi->ifi_index)
                continue;
            missing_net_address = 0;
            if (filter.family && filter.family != ifa->ifa_family)
                continue;
            if ((filter.scope ^ ifa->ifa_scope) & filter.scopemask)
                continue;

            parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(n));
            ifa_flags = get_ifa_flags(ifa, tb[IFA_FLAGS]);

            if ((filter.flags ^ ifa_flags) & filter.flagmask)
                continue;
            if (filter.pfx.family || filter.label) {
                if (!tb[IFA_LOCAL])
                    tb[IFA_LOCAL] = tb[IFA_ADDRESS];

                if (filter.pfx.family && tb[IFA_LOCAL]) {
                    inet_prefix dst = {
                            .family = ifa->ifa_family
                    };

                    memcpy(&dst.data, RTA_DATA(tb[IFA_LOCAL]), RTA_PAYLOAD(tb[IFA_LOCAL]));
                    if (inet_addr_match(&dst, &filter.pfx, filter.pfx.bitlen))
                        continue;
                }
                if (filter.label) {
                    SPRINT_BUF(b1);
                    const char *label;

                    if (tb[IFA_LABEL])
                        label = RTA_DATA(tb[IFA_LABEL]);
                    else
                        label = ll_idx_n2a(ifa->ifa_index, b1);
                    if (fnmatch(filter.label, label, 0) != 0)
                        continue;
                }
            }

            ok = 1;
            break;
        }
        if (missing_net_address &&
            (filter.family == AF_UNSPEC || filter.family == AF_PACKET))
            ok = 1;
        if (!ok) {
            *lp = l->next;
            free(l);
        } else
            lp = &l->next;
    }
}

static void print_ifa_flags(FILE *fp, const struct ifaddrmsg *ifa,
                            unsigned int flags) {
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ifa_flag_names); i++) {
        unsigned long mask = ifa_flag_names[i].value;

        if (mask == IFA_F_PERMANENT) {
            if (!(flags & mask))
                print_bool(PRINT_ANY,
                           "dynamic", "dynamic ", true);
        } else if (flags & mask) {
            if (mask == IFA_F_SECONDARY &&
                ifa->ifa_family == AF_INET6) {
                print_bool(PRINT_ANY,
                           "temporary", "temporary ", true);
            } else {
                print_string(PRINT_FP, NULL,
                             "%s ", ifa_flag_names[i].name);
                print_bool(PRINT_JSON,
                           ifa_flag_names[i].name, NULL, true);
            }
        }

        flags &= ~mask;
    }

    if (flags) {
        if (is_json_context()) {
            SPRINT_BUF(b1);

            snprintf(b1, sizeof(b1), "%02x", flags);
            print_string(PRINT_JSON, "ifa_flags", NULL, b1);
        } else {
            fprintf(fp, "flags %02x ", flags);
        }
    }

}

int print_addrinfo(const struct sockaddr_nl *who, struct nlmsghdr *n,
                   void *arg) {
    FILE *fp = arg;
    struct ifaddrmsg *ifa = NLMSG_DATA(n);
    int len = n->nlmsg_len;
    unsigned int ifa_flags;
    struct rtattr *rta_tb[IFA_MAX + 1];

    SPRINT_BUF(b1);

    if (n->nlmsg_type != RTM_NEWADDR && n->nlmsg_type != RTM_DELADDR)
        return 0;
    len -= NLMSG_LENGTH(sizeof(*ifa));
    if (len < 0) {
        fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
        return -1;
    }

    if (filter.flushb && n->nlmsg_type != RTM_NEWADDR)
        return 0;

    parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
                 n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

    ifa_flags = get_ifa_flags(ifa, rta_tb[IFA_FLAGS]);

    if (!rta_tb[IFA_LOCAL])
        rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
    if (!rta_tb[IFA_ADDRESS])
        rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

    if (filter.ifindex && filter.ifindex != ifa->ifa_index)
        return 0;
    if ((filter.scope ^ ifa->ifa_scope) & filter.scopemask)
        return 0;
    if ((filter.flags ^ ifa_flags) & filter.flagmask)
        return 0;
    if (filter.label) {
        SPRINT_BUF(b1);
        const char *label;

        if (rta_tb[IFA_LABEL])
            label = RTA_DATA(rta_tb[IFA_LABEL]);
        else
            label = ll_idx_n2a(ifa->ifa_index, b1);
        if (fnmatch(filter.label, label, 0) != 0)
            return 0;
    }
    if (filter.pfx.family) {
        if (rta_tb[IFA_LOCAL]) {
            inet_prefix dst = {.family = ifa->ifa_family};

            memcpy(&dst.data, RTA_DATA(rta_tb[IFA_LOCAL]), RTA_PAYLOAD(rta_tb[IFA_LOCAL]));
            if (inet_addr_match(&dst, &filter.pfx, filter.pfx.bitlen))
                return 0;
        }
    }

    if (filter.family && filter.family != ifa->ifa_family)
        return 0;

    if (filter.flushb) {
        struct nlmsghdr *fn;

        if (NLMSG_ALIGN(filter.flushp) + n->nlmsg_len > filter.flushe) {
            if (flush_update())
                return -1;
        }
        fn = (struct nlmsghdr *) (filter.flushb + NLMSG_ALIGN(filter.flushp));
        memcpy(fn, n, n->nlmsg_len);
        fn->nlmsg_type = RTM_DELADDR;
        fn->nlmsg_flags = NLM_F_REQUEST;
        fn->nlmsg_seq = ++rth.seq;
        filter.flushp = (((char *) fn) + n->nlmsg_len) - filter.flushb;
        filter.flushed++;
        if (show_stats < 2)
            return 0;
    }

    if (n->nlmsg_type == RTM_DELADDR)
        print_bool(PRINT_ANY, "deleted", "Deleted ", true);

    if (!brief) {
        if (filter.oneline || filter.flushb) {
            const char *dev = ll_index_to_name(ifa->ifa_index);

            if (is_json_context()) {
                print_int(PRINT_JSON,
                          "index", NULL, ifa->ifa_index);
                print_string(PRINT_JSON, "dev", NULL, dev);
            } else {
                fprintf(fp, "%u: %s", ifa->ifa_index, dev);
            }
        }

        int family = ifa->ifa_family;

        if (ifa->ifa_family == AF_INET)
            print_string(PRINT_ANY, "family", "    %s ", "inet");
        else if (ifa->ifa_family == AF_INET6)
            print_string(PRINT_ANY, "family", "    %s ", "inet6");
        else if (ifa->ifa_family == AF_DECnet)
            print_string(PRINT_ANY, "family", "    %s ", "dnet");
        else if (ifa->ifa_family == AF_IPX)
            print_string(PRINT_ANY, "family", "     %s ", "ipx");
        else
            print_int(PRINT_ANY,
                      "family_index",
                      "    family %d ", family);
    }

    if (rta_tb[IFA_LOCAL]) {
        print_color_string(PRINT_ANY,
                           ifa_family_color(ifa->ifa_family),
                           "local", "%s",
                           format_host_rta(ifa->ifa_family,
                                           rta_tb[IFA_LOCAL]));
        if (rta_tb[IFA_ADDRESS] &&
            memcmp(RTA_DATA(rta_tb[IFA_ADDRESS]),
                   RTA_DATA(rta_tb[IFA_LOCAL]),
                   ifa->ifa_family == AF_INET ? 4 : 16)) {
            print_string(PRINT_FP, NULL, " %s ", "peer");
            print_color_string(PRINT_ANY,
                               ifa_family_color(ifa->ifa_family),
                               "address",
                               "%s",
                               format_host_rta(ifa->ifa_family,
                                               rta_tb[IFA_ADDRESS]));
        }
        print_int(PRINT_ANY, "prefixlen", "/%d ", ifa->ifa_prefixlen);
    }

    if (brief)
        goto brief_exit;

    if (rta_tb[IFA_BROADCAST]) {
        print_string(PRINT_FP, NULL, "%s ", "brd");
        print_color_string(PRINT_ANY,
                           ifa_family_color(ifa->ifa_family),
                           "broadcast",
                           "%s ",
                           format_host_rta(ifa->ifa_family,
                                           rta_tb[IFA_BROADCAST]));
    }

    if (rta_tb[IFA_ANYCAST]) {
        print_string(PRINT_FP, NULL, "%s ", "any");
        print_color_string(PRINT_ANY,
                           ifa_family_color(ifa->ifa_family),
                           "anycast",
                           "%s ",
                           format_host_rta(ifa->ifa_family,
                                           rta_tb[IFA_ANYCAST]));
    }

    print_string(PRINT_ANY,
                 "scope",
                 "scope %s ",
                 rtnl_rtscope_n2a(ifa->ifa_scope, b1, sizeof(b1)));

    print_ifa_flags(fp, ifa, ifa_flags);

    if (rta_tb[IFA_LABEL])
        print_string(PRINT_ANY,
                     "label",
                     "%s",
                     rta_getattr_str(rta_tb[IFA_LABEL]));

    if (rta_tb[IFA_CACHEINFO]) {
        struct ifa_cacheinfo *ci = RTA_DATA(rta_tb[IFA_CACHEINFO]);

        print_string(PRINT_FP, NULL, "%s", _SL_);
        print_string(PRINT_FP, NULL, "       valid_lft ", NULL);

        if (ci->ifa_valid == INFINITY_LIFE_TIME) {
            print_uint(PRINT_JSON,
                       "valid_life_time",
                       NULL, INFINITY_LIFE_TIME);
            print_string(PRINT_FP, NULL, "%s", "forever");
        } else {
            print_uint(PRINT_ANY,
                       "valid_life_time", "%usec", ci->ifa_valid);
        }

        print_string(PRINT_FP, NULL, " preferred_lft ", NULL);
        if (ci->ifa_prefered == INFINITY_LIFE_TIME) {
            print_uint(PRINT_JSON,
                       "preferred_life_time",
                       NULL, INFINITY_LIFE_TIME);
            print_string(PRINT_FP, NULL, "%s", "forever");
        } else {
            if (ifa_flags & IFA_F_DEPRECATED)
                print_int(PRINT_ANY,
                          "preferred_life_time",
                          "%dsec",
                          ci->ifa_prefered);
            else
                print_uint(PRINT_ANY,
                           "preferred_life_time",
                           "%usec",
                           ci->ifa_prefered);
        }
    }
    print_string(PRINT_FP, NULL, "%s", "\n");
    brief_exit:
    fflush(fp);
    return 0;
}

static int print_selected_addrinfo(struct ifinfomsg *ifi,
                                   struct nlmsg_list *ainfo, FILE *fp) {
    open_json_array(PRINT_JSON, "addr_info");
    for (; ainfo; ainfo = ainfo->next) {
        struct nlmsghdr *n = &ainfo->h;
        struct ifaddrmsg *ifa = NLMSG_DATA(n);

        if (n->nlmsg_type != RTM_NEWADDR)
            continue;

        if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
            return -1;

        if (ifa->ifa_index != ifi->ifi_index ||
            (filter.family && filter.family != ifa->ifa_family))
            continue;

        if (filter.up && !(ifi->ifi_flags & IFF_UP))
            continue;

        open_json_object(NULL);
        print_addrinfo(NULL, n, fp);
        close_json_object();
    }
    close_json_array(PRINT_JSON, NULL);

    if (brief) {
        print_string(PRINT_FP, NULL, "%s", "\n");
        fflush(fp);
    }
    return 0;
}

static void print_link_stats64(FILE *fp, const struct rtnl_link_stats64 *s,
                               const struct rtattr *carrier_changes) {
    if (is_json_context()) {
        open_json_object("stats644");

        /* RX stats */
        open_json_object("rx");
        print_uint(PRINT_JSON, "bytes", NULL, s->rx_bytes);
        print_uint(PRINT_JSON, "packets", NULL, s->rx_packets);
        print_uint(PRINT_JSON, "errors", NULL, s->rx_errors);
        print_uint(PRINT_JSON, "dropped", NULL, s->rx_dropped);
        print_uint(PRINT_JSON, "over_errors", NULL, s->rx_over_errors);
        print_uint(PRINT_JSON, "multicast", NULL, s->multicast);
        if (s->rx_compressed)
            print_uint(PRINT_JSON,
                       "compressed",
                       NULL, s->rx_compressed);

        /* RX error stats */
        if (show_stats > 1) {
            print_uint(PRINT_JSON,
                       "length_errors",
                       NULL, s->rx_length_errors);
            print_uint(PRINT_JSON,
                       "crc_errors",
                       NULL, s->rx_crc_errors);
            print_uint(PRINT_JSON,
                       "frame_errors",
                       NULL, s->rx_frame_errors);
            print_uint(PRINT_JSON,
                       "fifo_errors",
                       NULL, s->rx_fifo_errors);
            print_uint(PRINT_JSON,
                       "missed_errors",
                       NULL, s->rx_missed_errors);
            if (s->rx_nohandler)
                print_uint(PRINT_JSON,
                           "nohandler", NULL, s->rx_nohandler);
        }
        close_json_object();

        /* TX stats */
        open_json_object("tx");
        print_uint(PRINT_JSON, "bytes", NULL, s->tx_bytes);
        print_uint(PRINT_JSON, "packets", NULL, s->tx_packets);
        print_uint(PRINT_JSON, "errors", NULL, s->tx_errors);
        print_uint(PRINT_JSON, "dropped", NULL, s->tx_dropped);
        print_uint(PRINT_JSON,
                   "carrier_errors",
                   NULL, s->tx_carrier_errors);
        print_uint(PRINT_JSON, "collisions", NULL, s->collisions);
        if (s->tx_compressed)
            print_uint(PRINT_JSON,
                       "compressed",
                       NULL, s->tx_compressed);

        /* TX error stats */
        if (show_stats > 1) {
            print_uint(PRINT_JSON,
                       "aborted_errors",
                       NULL, s->tx_aborted_errors);
            print_uint(PRINT_JSON,
                       "fifo_errors",
                       NULL, s->tx_fifo_errors);
            print_uint(PRINT_JSON,
                       "window_errors",
                       NULL, s->tx_window_errors);
            print_uint(PRINT_JSON,
                       "heartbeat_errors",
                       NULL, s->tx_heartbeat_errors);
            if (carrier_changes)
                print_uint(PRINT_JSON, "carrier_changes", NULL,
                           rta_getattr_u32(carrier_changes));
        }
        close_json_object();
        close_json_object();

    } else {
        /* RX stats */
        fprintf(fp, "    RX: bytes  packets  errors  dropped overrun mcast   %s%s",
                s->rx_compressed ? "compressed" : "", _SL_);

        fprintf(fp, "    ");
        print_num(fp, 10, s->rx_bytes);
        print_num(fp, 8, s->rx_packets);
        print_num(fp, 7, s->rx_errors);
        print_num(fp, 7, s->rx_dropped);
        print_num(fp, 7, s->rx_over_errors);
        print_num(fp, 7, s->multicast);
        if (s->rx_compressed)
            print_num(fp, 7, s->rx_compressed);

        /* RX error stats */
        if (show_stats > 1) {
            fprintf(fp, "%s", _SL_);
            fprintf(fp, "    RX errors: length   crc     frame   fifo    missed%s%s",
                    s->rx_nohandler ? "   nohandler" : "", _SL_);

            fprintf(fp, "               ");
            print_num(fp, 8, s->rx_length_errors);
            print_num(fp, 7, s->rx_crc_errors);
            print_num(fp, 7, s->rx_frame_errors);
            print_num(fp, 7, s->rx_fifo_errors);
            print_num(fp, 7, s->rx_missed_errors);
            if (s->rx_nohandler)
                print_num(fp, 7, s->rx_nohandler);

        }
        fprintf(fp, "%s", _SL_);

        /* TX stats */
        fprintf(fp, "    TX: bytes  packets  errors  dropped carrier collsns %s%s",
                s->tx_compressed ? "compressed" : "", _SL_);

        fprintf(fp, "    ");
        print_num(fp, 10, s->tx_bytes);
        print_num(fp, 8, s->tx_packets);
        print_num(fp, 7, s->tx_errors);
        print_num(fp, 7, s->tx_dropped);
        print_num(fp, 7, s->tx_carrier_errors);
        print_num(fp, 7, s->collisions);
        if (s->tx_compressed)
            print_num(fp, 7, s->tx_compressed);

        /* TX error stats */
        if (show_stats > 1) {
            fprintf(fp, "%s", _SL_);
            fprintf(fp, "    TX errors: aborted  fifo   window heartbeat");
            if (carrier_changes)
                fprintf(fp, " transns");
            fprintf(fp, "%s", _SL_);

            fprintf(fp, "               ");
            print_num(fp, 8, s->tx_aborted_errors);
            print_num(fp, 7, s->tx_fifo_errors);
            print_num(fp, 7, s->tx_window_errors);
            print_num(fp, 7, s->tx_heartbeat_errors);
            if (carrier_changes)
                print_num(fp, 7,
                          rta_getattr_u32(carrier_changes));
        }
    }
}

static void print_link_stats32(FILE *fp, const struct rtnl_link_stats *s,
                               const struct rtattr *carrier_changes) {
    if (is_json_context()) {
        open_json_object("stats");

        /* RX stats */
        open_json_object("rx");
        print_uint(PRINT_JSON, "bytes", NULL, s->rx_bytes);
        print_uint(PRINT_JSON, "packets", NULL, s->rx_packets);
        print_uint(PRINT_JSON, "errors", NULL, s->rx_errors);
        print_uint(PRINT_JSON, "dropped", NULL, s->rx_dropped);
        print_uint(PRINT_JSON, "over_errors", NULL, s->rx_over_errors);
        print_uint(PRINT_JSON, "multicast", NULL, s->multicast);
        if (s->rx_compressed)
            print_int(PRINT_JSON,
                      "compressed",
                      NULL, s->rx_compressed);

        /* RX error stats */
        if (show_stats > 1) {
            print_uint(PRINT_JSON,
                       "length_errors",
                       NULL, s->rx_length_errors);
            print_uint(PRINT_JSON,
                       "crc_errors",
                       NULL, s->rx_crc_errors);
            print_uint(PRINT_JSON,
                       "frame_errors",
                       NULL, s->rx_frame_errors);
            print_uint(PRINT_JSON,
                       "fifo_errors",
                       NULL, s->rx_fifo_errors);
            print_uint(PRINT_JSON,
                       "missed_errors",
                       NULL, s->rx_missed_errors);
            if (s->rx_nohandler)
                print_int(PRINT_JSON,
                          "nohandler",
                          NULL, s->rx_nohandler);
        }
        close_json_object();

        /* TX stats */
        open_json_object("tx");
        print_uint(PRINT_JSON, "bytes", NULL, s->tx_bytes);
        print_uint(PRINT_JSON, "packets", NULL, s->tx_packets);
        print_uint(PRINT_JSON, "errors", NULL, s->tx_errors);
        print_uint(PRINT_JSON, "dropped", NULL, s->tx_dropped);
        print_uint(PRINT_JSON,
                   "carrier_errors",
                   NULL, s->tx_carrier_errors);
        print_uint(PRINT_JSON, "collisions", NULL, s->collisions);
        if (s->tx_compressed)
            print_int(PRINT_JSON,
                      "compressed",
                      NULL, s->tx_compressed);

        /* TX error stats */
        if (show_stats > 1) {
            print_uint(PRINT_JSON,
                       "aborted_errors",
                       NULL, s->tx_aborted_errors);
            print_uint(PRINT_JSON,
                       "fifo_errors",
                       NULL, s->tx_fifo_errors);
            print_uint(PRINT_JSON,
                       "window_errors",
                       NULL, s->tx_window_errors);
            print_uint(PRINT_JSON,
                       "heartbeat_errors",
                       NULL, s->tx_heartbeat_errors);
            if (carrier_changes)
                print_uint(PRINT_JSON,
                           "carrier_changes",
                           NULL,
                           rta_getattr_u32(carrier_changes));
        }

        close_json_object();
        close_json_object();
    } else {
        /* RX stats */
        fprintf(fp, "    RX: bytes  packets  errors  dropped overrun mcast   %s%s",
                s->rx_compressed ? "compressed" : "", _SL_);


        fprintf(fp, "    ");
        print_num(fp, 10, s->rx_bytes);
        print_num(fp, 8, s->rx_packets);
        print_num(fp, 7, s->rx_errors);
        print_num(fp, 7, s->rx_dropped);
        print_num(fp, 7, s->rx_over_errors);
        print_num(fp, 7, s->multicast);
        if (s->rx_compressed)
            print_num(fp, 7, s->rx_compressed);

        /* RX error stats */
        if (show_stats > 1) {
            fprintf(fp, "%s", _SL_);
            fprintf(fp, "    RX errors: length   crc     frame   fifo    missed%s%s",
                    s->rx_nohandler ? "   nohandler" : "", _SL_);
            fprintf(fp, "               ");
            print_num(fp, 8, s->rx_length_errors);
            print_num(fp, 7, s->rx_crc_errors);
            print_num(fp, 7, s->rx_frame_errors);
            print_num(fp, 7, s->rx_fifo_errors);
            print_num(fp, 7, s->rx_missed_errors);
            if (s->rx_nohandler)
                print_num(fp, 7, s->rx_nohandler);
        }
        fprintf(fp, "%s", _SL_);

        /* TX stats */
        fprintf(fp, "    TX: bytes  packets  errors  dropped carrier collsns %s%s",
                s->tx_compressed ? "compressed" : "", _SL_);

        fprintf(fp, "    ");
        print_num(fp, 10, s->tx_bytes);
        print_num(fp, 8, s->tx_packets);
        print_num(fp, 7, s->tx_errors);
        print_num(fp, 7, s->tx_dropped);
        print_num(fp, 7, s->tx_carrier_errors);
        print_num(fp, 7, s->collisions);
        if (s->tx_compressed)
            print_num(fp, 7, s->tx_compressed);

        /* TX error stats */
        if (show_stats > 1) {
            fprintf(fp, "%s", _SL_);
            fprintf(fp, "    TX errors: aborted  fifo   window heartbeat");
            if (carrier_changes)
                fprintf(fp, " transns");
            fprintf(fp, "%s", _SL_);

            fprintf(fp, "               ");
            print_num(fp, 8, s->tx_aborted_errors);
            print_num(fp, 7, s->tx_fifo_errors);
            print_num(fp, 7, s->tx_window_errors);
            print_num(fp, 7, s->tx_heartbeat_errors);
            if (carrier_changes)
                print_num(fp, 7,
                          rta_getattr_u32(carrier_changes));
        }
    }
}

static void __print_link_stats(FILE *fp, struct rtattr **tb) {
    const struct rtattr *carrier_changes = tb[IFLA_CARRIER_CHANGES];

    if (tb[IFLA_STATS64]) {
        struct rtnl_link_stats64 stats = {0};

        memcpy(&stats, RTA_DATA(tb[IFLA_STATS64]),
               MIN(RTA_PAYLOAD(tb[IFLA_STATS64]), sizeof(stats)));

        print_link_stats64(fp, &stats, carrier_changes);
    } else if (tb[IFLA_STATS]) {
        struct rtnl_link_stats stats = {0};

        memcpy(&stats, RTA_DATA(tb[IFLA_STATS]),
               MIN(RTA_PAYLOAD(tb[IFLA_STATS]), sizeof(stats)));

        print_link_stats32(fp, &stats, carrier_changes);
    }
}

static void print_link_stats(FILE *fp, struct nlmsghdr *n) {
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct rtattr *tb[IFLA_MAX + 1];

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi),
                 n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
    __print_link_stats(fp, tb);
    fprintf(fp, "%s", _SL_);
}

static int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n,
                       void *arg) {
    struct nlmsg_chain *lchain = (struct nlmsg_chain *) arg;
    struct nlmsg_list *h;

    h = malloc(n->nlmsg_len + sizeof(void *));
    if (h == NULL)
        return -1;

    memcpy(&h->h, n, n->nlmsg_len);
    h->next = NULL;

    if (lchain->tail)
        lchain->tail->next = h;
    else
        lchain->head = h;
    lchain->tail = h;

    ll_remember_index(who, n, NULL);
    return 0;
}

/* fills in linfo with link data and optionally ainfo with address info
 * caller can walk lists as desired and must call free_nlmsg_chain for
 * both when done
 */
int ip_linkaddr_list(int family, req_filter_fn_t filter_fn,
                     struct nlmsg_chain *linfo, struct nlmsg_chain *ainfo) {
    if (rtnl_wilddump_req_filter_fn(&rth, preferred_family, RTM_GETLINK,
                                    filter_fn) < 0) {
        perror("Cannot send dump request");
        return 1;
    }

    if (rtnl_dump_filter(&rth, store_nlmsg, linfo) < 0) {
        fprintf(stderr, "Dump terminated\n");
        return 1;
    }

    if (ainfo) {
        if (rtnl_wilddump_request(&rth, family, RTM_GETADDR) < 0) {
            perror("Cannot send dump request");
            return 1;
        }

        if (rtnl_dump_filter(&rth, store_nlmsg, ainfo) < 0) {
            fprintf(stderr, "Dump terminated\n");
            return 1;
        }
    }

    return 0;
}

static void print_operstate(FILE *f, __u8 state) {
    if (state >= ARRAY_SIZE(oper_states)) {
        if (is_json_context())
            print_uint(PRINT_JSON, "operstate_index", NULL, state);
        else
            print_0xhex(PRINT_FP, NULL, "state %#x", state);
    } else if (brief) {
        print_color_string(PRINT_ANY,
                           oper_state_color(state),
                           "operstate",
                           "%-14s ",
                           oper_states[state]);
    } else {
        if (is_json_context())
            print_string(PRINT_JSON,
                         "operstate",
                         NULL, oper_states[state]);
        else {
            fprintf(f, "state ");
            color_fprintf(f, oper_state_color(state),
                          "%s ", oper_states[state]);
        }
    }
}

static char *parse_link_kind(struct rtattr *tb, bool slave) {
    struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
    int attr = slave ? IFLA_INFO_SLAVE_KIND : IFLA_INFO_KIND;

    parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);

    if (linkinfo[attr])
        return RTA_DATA(linkinfo[attr]);

    return "";
}

static int match_link_kind(struct rtattr **tb, const char *kind, bool slave) {
    if (!tb[IFLA_LINKINFO])
        return -1;

    return strcmp(parse_link_kind(tb[IFLA_LINKINFO], slave), kind);
}

static void print_link_flags(FILE *fp, unsigned int flags, unsigned int mdown) {
    open_json_array(PRINT_ANY, is_json_context() ? "flags" : "<");
    if (flags & IFF_UP && !(flags & IFF_RUNNING))
        print_string(PRINT_ANY, NULL,
                     flags ? "%s," : "%s", "NO-CARRIER");
    flags &= ~IFF_RUNNING;
#define _PF(f) if (flags&IFF_##f) {                    \
        flags &= ~IFF_##f ;                    \
        print_string(PRINT_ANY, NULL, flags ? "%s," : "%s", #f); }
    _PF(LOOPBACK);
    _PF(BROADCAST);
    _PF(POINTOPOINT);
    _PF(MULTICAST);
    _PF(NOARP);
    _PF(ALLMULTI);
    _PF(PROMISC);
    _PF(MASTER);
    _PF(SLAVE);
    _PF(DEBUG);
    _PF(DYNAMIC);
    _PF(AUTOMEDIA);
    _PF(PORTSEL);
    _PF(NOTRAILERS);
    _PF(UP);
    _PF(LOWER_UP);
    _PF(DORMANT);
    _PF(ECHO);
#undef _PF
    if (flags)
        print_hex(PRINT_ANY, NULL, "%x", flags);
    if (mdown)
        print_string(PRINT_ANY, NULL, ",%s", "M-DOWN");
    close_json_array(PRINT_ANY, "> ");
}

static void print_vf_stats64(FILE *fp, struct rtattr *vfstats) {
    struct rtattr *vf[IFLA_VF_STATS_MAX + 1];

    if (vfstats->rta_type != IFLA_VF_STATS) {
        fprintf(stderr, "BUG: rta type is %d\n", vfstats->rta_type);
        return;
    }

    parse_rtattr_nested(vf, IFLA_VF_MAX, vfstats);

    if (is_json_context()) {
        open_json_object("stats");

        /* RX stats */
        open_json_object("rx");
        print_uint(PRINT_JSON, "bytes", NULL,
                   rta_getattr_u64(vf[IFLA_VF_STATS_RX_BYTES]));
        print_uint(PRINT_JSON, "packets", NULL,
                   rta_getattr_u64(vf[IFLA_VF_STATS_RX_PACKETS]));
        print_uint(PRINT_JSON, "multicast", NULL,
                   rta_getattr_u64(vf[IFLA_VF_STATS_MULTICAST]));
        print_uint(PRINT_JSON, "broadcast", NULL,
                   rta_getattr_u64(vf[IFLA_VF_STATS_BROADCAST]));
        close_json_object();

        /* TX stats */
        open_json_object("tx");
        print_uint(PRINT_JSON, "tx_bytes", NULL,
                   rta_getattr_u64(vf[IFLA_VF_STATS_TX_BYTES]));
        print_uint(PRINT_JSON, "tx_packets", NULL,
                   rta_getattr_u64(vf[IFLA_VF_STATS_TX_PACKETS]));
        close_json_object();
        close_json_object();
    } else {
        /* RX stats */
        fprintf(fp, "%s", _SL_);
        fprintf(fp, "    RX: bytes  packets  mcast   bcast %s", _SL_);
        fprintf(fp, "    ");

        print_num(fp, 10, rta_getattr_u64(vf[IFLA_VF_STATS_RX_BYTES]));
        print_num(fp, 8, rta_getattr_u64(vf[IFLA_VF_STATS_RX_PACKETS]));
        print_num(fp, 7, rta_getattr_u64(vf[IFLA_VF_STATS_MULTICAST]));
        print_num(fp, 7, rta_getattr_u64(vf[IFLA_VF_STATS_BROADCAST]));

        /* TX stats */
        fprintf(fp, "%s", _SL_);
        fprintf(fp, "    TX: bytes  packets %s", _SL_);
        fprintf(fp, "    ");

        print_num(fp, 10, rta_getattr_u64(vf[IFLA_VF_STATS_TX_BYTES]));
        print_num(fp, 8, rta_getattr_u64(vf[IFLA_VF_STATS_TX_PACKETS]));
    }
}

static void print_vfinfo(FILE *fp, struct rtattr *vfinfo) {
    struct ifla_vf_mac *vf_mac;
    struct ifla_vf_tx_rate *vf_tx_rate;
    struct rtattr *vf[IFLA_VF_MAX + 1] = {};

    SPRINT_BUF(b1);

    if (vfinfo->rta_type != IFLA_VF_INFO) {
        fprintf(stderr, "BUG: rta type is %d\n", vfinfo->rta_type);
        return;
    }

    parse_rtattr_nested(vf, IFLA_VF_MAX, vfinfo);

    vf_mac = RTA_DATA(vf[IFLA_VF_MAC]);
    vf_tx_rate = RTA_DATA(vf[IFLA_VF_TX_RATE]);

    print_string(PRINT_FP, NULL, "%s    ", _SL_);
    print_int(PRINT_ANY, "vf", "vf %d ", vf_mac->vf);
    print_string(PRINT_ANY, "mac", "MAC %s",
                 ll_addr_n2a((unsigned char *) &vf_mac->mac,
                             ETH_ALEN, 0, b1, sizeof(b1)));

    if (vf[IFLA_VF_VLAN_LIST]) {
        struct rtattr *i, *vfvlanlist = vf[IFLA_VF_VLAN_LIST];
        int rem = RTA_PAYLOAD(vfvlanlist);

        open_json_array(PRINT_JSON, "vlan_list");
        for (i = RTA_DATA(vfvlanlist);
             RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
            struct ifla_vf_vlan_info *vf_vlan_info = RTA_DATA(i);
            SPRINT_BUF(b2);

            open_json_object(NULL);
            if (vf_vlan_info->vlan)
                print_int(PRINT_ANY,
                          "vlan",
                          ", vlan %d",
                          vf_vlan_info->vlan);
            if (vf_vlan_info->qos)
                print_int(PRINT_ANY,
                          "qos",
                          ", qos %d",
                          vf_vlan_info->qos);
            if (vf_vlan_info->vlan_proto &&
                vf_vlan_info->vlan_proto != htons(ETH_P_8021Q))
                print_string(PRINT_ANY,
                             "protocol",
                             ", vlan protocol %s",
                             ll_proto_n2a(
                                     vf_vlan_info->vlan_proto,
                                     b2, sizeof(b2)));
            close_json_object();
        }
        close_json_array(PRINT_JSON, NULL);
    } else {
        struct ifla_vf_vlan *vf_vlan = RTA_DATA(vf[IFLA_VF_VLAN]);

        if (vf_vlan->vlan)
            print_int(PRINT_ANY,
                      "vlan",
                      ", vlan %d",
                      vf_vlan->vlan);
        if (vf_vlan->qos)
            print_int(PRINT_ANY, "qos", ", qos %d", vf_vlan->qos);
    }

    if (vf_tx_rate->rate)
        print_int(PRINT_ANY,
                  "tx_rate",
                  ", tx rate %d (Mbps)",
                  vf_tx_rate->rate);

    if (vf[IFLA_VF_RATE]) {
        struct ifla_vf_rate *vf_rate = RTA_DATA(vf[IFLA_VF_RATE]);
        int max_tx = vf_rate->max_tx_rate;
        int min_tx = vf_rate->min_tx_rate;

        if (is_json_context()) {
            open_json_object("rate");
            print_int(PRINT_JSON, "max_tx", NULL, max_tx);
            print_int(PRINT_ANY, "min_tx", NULL, min_tx);
            close_json_object();
        } else {
            if (max_tx)
                fprintf(fp, ", max_tx_rate %dMbps", max_tx);
            if (min_tx)
                fprintf(fp, ", min_tx_rate %dMbps", min_tx);
        }
    }

    if (vf[IFLA_VF_SPOOFCHK]) {
        struct ifla_vf_spoofchk *vf_spoofchk =
                RTA_DATA(vf[IFLA_VF_SPOOFCHK]);

        if (vf_spoofchk->setting != -1)
            print_bool(PRINT_ANY,
                       "spoofchk",
                       vf_spoofchk->setting ?
                       ", spoof checking on" : ", spoof checking off",
                       vf_spoofchk->setting);
    }

    if (vf[IFLA_VF_LINK_STATE]) {
        struct ifla_vf_link_state *vf_linkstate =
                RTA_DATA(vf[IFLA_VF_LINK_STATE]);

        if (vf_linkstate->link_state == IFLA_VF_LINK_STATE_AUTO)
            print_string(PRINT_ANY,
                         "link_state",
                         ", link-state %s",
                         "auto");
        else if (vf_linkstate->link_state == IFLA_VF_LINK_STATE_ENABLE)
            print_string(PRINT_ANY,
                         "link_state",
                         ", link-state %s",
                         "enable");
        else
            print_string(PRINT_ANY,
                         "link_state",
                         ", link-state %s",
                         "disable");
    }

    if (vf[IFLA_VF_TRUST]) {
        struct ifla_vf_trust *vf_trust = RTA_DATA(vf[IFLA_VF_TRUST]);

        if (vf_trust->setting != -1)
            print_bool(PRINT_ANY,
                       "trust",
                       vf_trust->setting ? ", trust on" : ", trust off",
                       vf_trust->setting);
    }

    if (vf[IFLA_VF_RSS_QUERY_EN]) {
        struct ifla_vf_rss_query_en *rss_query =
                RTA_DATA(vf[IFLA_VF_RSS_QUERY_EN]);

        if (rss_query->setting != -1)
            print_bool(PRINT_ANY,
                       "query_rss_en",
                       rss_query->setting ? ", query_rss on"
                                          : ", query_rss off",
                       rss_query->setting);
    }

    if (vf[IFLA_VF_STATS] && show_stats)
        print_vf_stats64(fp, vf[IFLA_VF_STATS]);
}

static const char *link_modes[] = {
        "DEFAULT", "DORMANT"
};

static void print_linkmode(FILE *f, struct rtattr *tb) {
    unsigned int mode = rta_getattr_u8(tb);

    if (mode >= ARRAY_SIZE(link_modes))
        print_int(PRINT_ANY,
                  "linkmode_index",
                  "mode %d ",
                  mode);
    else
        print_string(PRINT_ANY,
                     "linkmode",
                     "mode %s ", link_modes[mode]);
}

static void print_queuelen(FILE *f, struct rtattr *tb[IFLA_MAX + 1]) {
    int qlen;

    if (tb[IFLA_TXQLEN])
        qlen = rta_getattr_u32(tb[IFLA_TXQLEN]);
    else {
        struct ifreq ifr = {};
        int s = socket(AF_INET, SOCK_STREAM, 0);

        if (s < 0)
            return;

        strcpy(ifr.ifr_name, rta_getattr_str(tb[IFLA_IFNAME]));
        if (ioctl(s, SIOCGIFTXQLEN, &ifr) < 0) {
            fprintf(f, "ioctl(SIOCGIFTXQLEN) failed: %s\n", strerror(errno));
            close(s);
            return;
        }
        close(s);
        qlen = ifr.ifr_qlen;
    }
    if (qlen)
        print_int(PRINT_ANY, "txqlen", "qlen %d", qlen);
}

static const char *link_events[] = {
        [IFLA_EVENT_NONE] = "NONE",
        [IFLA_EVENT_REBOOT] = "REBOOT",
        [IFLA_EVENT_FEATURES] = "FEATURE CHANGE",
        [IFLA_EVENT_BONDING_FAILOVER] = "BONDING FAILOVER",
        [IFLA_EVENT_NOTIFY_PEERS] = "NOTIFY PEERS",
        [IFLA_EVENT_IGMP_RESEND] = "RESEND IGMP",
        [IFLA_EVENT_BONDING_OPTIONS] = "BONDING OPTION"
};

static void print_link_event(FILE *f, __u32 event) {
    if (event >= ARRAY_SIZE(link_events))
        print_int(PRINT_ANY, "event", "event %d ", event);
    else {
        if (event)
            print_string(PRINT_ANY,
                         "event", "event %s ",
                         link_events[event]);
    }
}

static void print_linktype(FILE *fp, struct rtattr *tb) {
    struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
    struct link_util *lu;
    struct link_util *slave_lu;
    char slave[32];

    parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);
    open_json_object("linkinfo");

    if (linkinfo[IFLA_INFO_KIND]) {
        const char *kind
                = rta_getattr_str(linkinfo[IFLA_INFO_KIND]);

        print_string(PRINT_FP, NULL, "%s", _SL_);
        print_string(PRINT_ANY, "info_kind", "    %s ", kind);

        lu = get_link_kind(kind);
        if (lu && lu->print_opt) {
            struct rtattr *attr[lu->maxattr + 1], **data = NULL;

            if (linkinfo[IFLA_INFO_DATA]) {
                parse_rtattr_nested(attr, lu->maxattr,
                                    linkinfo[IFLA_INFO_DATA]);
                data = attr;
            }
            open_json_object("info_data");
            lu->print_opt(lu, fp, data);
            close_json_object();

            if (linkinfo[IFLA_INFO_XSTATS] && show_stats &&
                lu->print_xstats) {
                open_json_object("info_xstats");
                lu->print_xstats(lu, fp, linkinfo[IFLA_INFO_XSTATS]);
                close_json_object();
            }
        }
    }

    if (linkinfo[IFLA_INFO_SLAVE_KIND]) {
        const char *slave_kind
                = rta_getattr_str(linkinfo[IFLA_INFO_SLAVE_KIND]);

        print_string(PRINT_FP, NULL, "%s", _SL_);
        print_string(PRINT_ANY,
                     "info_slave_kind",
                     "    %s_slave ",
                     slave_kind);

        snprintf(slave, sizeof(slave), "%s_slave", slave_kind);

        slave_lu = get_link_kind(slave);
        if (slave_lu && slave_lu->print_opt) {
            struct rtattr *attr[slave_lu->maxattr + 1], **data = NULL;

            if (linkinfo[IFLA_INFO_SLAVE_DATA]) {
                parse_rtattr_nested(attr, slave_lu->maxattr,
                                    linkinfo[IFLA_INFO_SLAVE_DATA]);
                data = attr;
            }
            open_json_object("info_slave_data");
            slave_lu->print_opt(slave_lu, fp, data);
            close_json_object();
        }
    }
    close_json_object();
}

static void print_af_spec(FILE *fp, struct rtattr *af_spec_attr) {
    struct rtattr *inet6_attr;
    struct rtattr *tb[IFLA_INET6_MAX + 1];

    inet6_attr = parse_rtattr_one_nested(AF_INET6, af_spec_attr);
    if (!inet6_attr)
        return;

    parse_rtattr_nested(tb, IFLA_INET6_MAX, inet6_attr);

    if (tb[IFLA_INET6_ADDR_GEN_MODE]) {
        __u8 mode = rta_getattr_u8(tb[IFLA_INET6_ADDR_GEN_MODE]);
        SPRINT_BUF(b1);

        switch (mode) {
            case IN6_ADDR_GEN_MODE_EUI64:
                print_string(PRINT_ANY,
                             "inet6_addr_gen_mode",
                             "addrgenmode %s ",
                             "eui64");
                break;
            case IN6_ADDR_GEN_MODE_NONE:
                print_string(PRINT_ANY,
                             "inet6_addr_gen_mode",
                             "addrgenmode %s ",
                             "none");
                break;
            case IN6_ADDR_GEN_MODE_STABLE_PRIVACY:
                print_string(PRINT_ANY,
                             "inet6_addr_gen_mode",
                             "addrgenmode %s ",
                             "stable_secret");
                break;
            case IN6_ADDR_GEN_MODE_RANDOM:
                print_string(PRINT_ANY,
                             "inet6_addr_gen_mode",
                             "addrgenmode %s ",
                             "random");
                break;
            default:
                snprintf(b1, sizeof(b1), "%#.2hhx", mode);
                print_string(PRINT_ANY,
                             "inet6_addr_gen_mode",
                             "addrgenmode %s ",
                             b1);
                break;
        }
    }
}

static int ipaddr_list_flush_or_save(int argc, char **argv, int action) {
    struct nlmsg_chain linfo = {NULL, NULL};
    struct nlmsg_chain _ainfo = {NULL, NULL}, *ainfo = NULL;
    struct nlmsg_list *l;
    char *filter_dev = NULL;
    int no_link = 0;

    ipaddr_reset_filter(oneline, 0);
    filter.showqueue = 1;
    filter.family = preferred_family;
    filter.group = -1;

    if (action == IPADD_FLUSH) {
        if (argc <= 0) {
            fprintf(stderr, "Flush requires arguments.\n");

            return -1;
        }
        if (filter.family == AF_PACKET) {
            fprintf(stderr, "Cannot flush link addresses.\n");
            return -1;
        }
    }

    while (argc > 0) {
        if (strcmp(*argv, "to") == 0) {
            NEXT_ARG();
            get_prefix(&filter.pfx, *argv, filter.family);
            if (filter.family == AF_UNSPEC)
                filter.family = filter.pfx.family;
        } else if (strcmp(*argv, "scope") == 0) {
            unsigned int scope = 0;

            NEXT_ARG();
            filter.scopemask = -1;
            if (rtnl_rtscope_a2n(&scope, *argv)) {
                if (strcmp(*argv, "all") != 0)
                    invarg("invalid \"scope\"\n", *argv);
                scope = RT_SCOPE_NOWHERE;
                filter.scopemask = 0;
            }
            filter.scope = scope;
        } else if (strcmp(*argv, "up") == 0) {
            filter.up = 1;
        } else if (get_filter(*argv) == 0) {

        } else if (strcmp(*argv, "label") == 0) {
            NEXT_ARG();
            filter.label = *argv;
        } else if (strcmp(*argv, "group") == 0) {
            NEXT_ARG();
            if (rtnl_group_a2n(&filter.group, *argv))
                invarg("Invalid \"group\" value\n", *argv);
        } else if (strcmp(*argv, "master") == 0) {
            int ifindex;

            NEXT_ARG();
            ifindex = ll_name_to_index(*argv);
            if (!ifindex)
                invarg("Device does not exist\n", *argv);
            filter.master = ifindex;
        } else if (strcmp(*argv, "vrf") == 0) {
            int ifindex;

            NEXT_ARG();
            ifindex = ll_name_to_index(*argv);
            if (!ifindex)
                invarg("Not a valid VRF name\n", *argv);
            if (!name_is_vrf(*argv))
                invarg("Not a valid VRF name\n", *argv);
            filter.master = ifindex;
        } else if (strcmp(*argv, "type") == 0) {
            int soff;

            NEXT_ARG();
            soff = strlen(*argv) - strlen("_slave");
            if (!strcmp(*argv + soff, "_slave")) {
                (*argv)[soff] = '\0';
                filter.slave_kind = *argv;
            } else {
                filter.kind = *argv;
            }
        } else {  //这里

            if (strcmp(*argv, "dev") == 0) {
                NEXT_ARG();
            } else if (matches(*argv, "help") == 0) {
                usage();
            }
            if (filter_dev) {
                duparg2("dev", *argv);
            }
            filter_dev = *argv;
        }
        argv++;
        argc--;
    }

    if (filter_dev) {
        filter.ifindex = ll_name_to_index(filter_dev);
        if (filter.ifindex <= 0) {
            fprintf(stderr, "Device \"%s\" does not exist.\n", filter_dev);
            return -1;
        }
    }

    if (action == IPADD_FLUSH)
        return ipaddr_flush();

    if (action == IPADD_SAVE) {
        if (ipadd_save_prep())
            exit(1);

        if (rtnl_wilddump_request(&rth, preferred_family, RTM_GETADDR) < 0) {
            perror("Cannot send dump request");
            exit(1);
        }

        if (rtnl_dump_filter(&rth, save_nlmsg, stdout) < 0) {
            fprintf(stderr, "Save terminated\n");
            exit(1);
        }

        exit(0);
    }

    /*
     * Initialize a json_writer and open an array object
     * if -json was specified.
     */
    new_json_obj(json);

    /*
     * If only filter_dev present and none of the other
     * link filters are present, use RTM_GETLINK to get
     * the link device
     */
    if (filter_dev && filter.group == -1 && do_link == 1) {
        if (iplink_get(0, filter_dev, RTEXT_FILTER_VF) < 0) {
            perror("Cannot send link get request");
            delete_json_obj();
            exit(1);
        }
        delete_json_obj();
        exit(0);
    }

    if (filter.family != AF_PACKET) {
        ainfo = &_ainfo;

        if (filter.oneline)
            no_link = 1;
    }

    if (ip_linkaddr_list(filter.family, iplink_filter_req,
                         &linfo, ainfo) != 0)
        goto out;

    if (filter.family != AF_PACKET)
        ipaddr_filter(&linfo, ainfo);

    for (l = linfo.head; l; l = l->next) {
        int res = 0;
        struct ifinfomsg *ifi = NLMSG_DATA(&l->h);

        open_json_object(NULL);
        if (brief) {
            if (print_linkinfo_brief(NULL, &l->h,
                                     stdout, NULL) == 0)
                if (filter.family != AF_PACKET)
                    print_selected_addrinfo(ifi,
                                            ainfo->head,
                                            stdout);
        } else if (no_link ||
                   //应该是在这里打印出来的
                   (res = print_linkinfo(NULL, &l->h, stdout)) >= 0) {
            if (filter.family != AF_PACKET) {
                print_selected_addrinfo(ifi,
                                        ainfo->head, stdout);
            }

            if (res > 0 && !do_link && show_stats) {
                print_link_stats(stdout, &l->h);
            }
        }
        close_json_object();
    }
    fflush(stdout);

    out:
    if (ainfo)
        free_nlmsg_chain(ainfo);
    free_nlmsg_chain(&linfo);
    delete_json_obj();
    return 0;
}

int ipaddr_list_link(int argc, char **argv) {
    preferred_family = AF_PACKET;
    do_link = 1;
    return ipaddr_list_flush_or_save(argc, argv, IPADD_LIST);
}

static void
ipaddr_loop_each_vf(struct rtattr *tb[], int vfnum, int *min, int *max) {
    struct rtattr *vflist = tb[IFLA_VFINFO_LIST];
    struct rtattr *i, *vf[IFLA_VF_MAX + 1];
    struct ifla_vf_rate *vf_rate;
    int rem;

    rem = RTA_PAYLOAD(vflist);

    for (i = RTA_DATA(vflist); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
        parse_rtattr_nested(vf, IFLA_VF_MAX, i);
        vf_rate = RTA_DATA(vf[IFLA_VF_RATE]);
        if (vf_rate->vf == vfnum) {
            *min = vf_rate->min_tx_rate;
            *max = vf_rate->max_tx_rate;
            return;
        }
    }
    fprintf(stderr, "Cannot find VF %d\n", vfnum);
    exit(1);
}

void ipaddr_get_vf_rate(int vfnum, int *min, int *max, int idx) {
    struct nlmsg_chain linfo = {NULL, NULL};
    struct rtattr *tb[IFLA_MAX + 1];
    struct ifinfomsg *ifi;
    struct nlmsg_list *l;
    struct nlmsghdr *n;
    int len;

    if (rtnl_wilddump_request(&rth, AF_UNSPEC, RTM_GETLINK) < 0) {
        perror("Cannot send dump request");
        exit(1);
    }
    if (rtnl_dump_filter(&rth, store_nlmsg, &linfo) < 0) {
        fprintf(stderr, "Dump terminated\n");
        exit(1);
    }
    for (l = linfo.head; l; l = l->next) {
        n = &l->h;
        ifi = NLMSG_DATA(n);

        len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
        if (len < 0 || (idx && idx != ifi->ifi_index))
            continue;

        parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

        if ((tb[IFLA_VFINFO_LIST] && tb[IFLA_NUM_VF])) {
            ipaddr_loop_each_vf(tb, vfnum, min, max);
            return;
        }
    }
}

int get_operstate(const char *name) {
    int i;

    for (i = 0; i < ARRAY_SIZE(oper_states); i++)
        if (strcasecmp(name, oper_states[i]) == 0)
            return i;
    return -1;
}

void free_nlmsg_chain(struct nlmsg_chain *info) {
    struct nlmsg_list *l, *n;

    for (l = info->head; l; l = n) {
        n = l->next;
        free(l);
    }
}


int print_linkinfo(const struct sockaddr_nl *who,
                   struct nlmsghdr *n, void *arg) {
    FILE *fp = (FILE *) arg;
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct rtattr *tb[IFLA_MAX + 1];
    int len = n->nlmsg_len;
    unsigned int m_flag = 0;

    if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
        return 0;

    len -= NLMSG_LENGTH(sizeof(*ifi));
    if (len < 0)
        return -1;

    if (filter.ifindex && ifi->ifi_index != filter.ifindex)
        return 0;
    if (filter.up && !(ifi->ifi_flags & IFF_UP))
        return 0;

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
    if (tb[IFLA_IFNAME] == NULL)
        fprintf(stderr, "BUG: device with ifindex %d has nil ifname\n", ifi->ifi_index);

    if (filter.label &&
        (!filter.family || filter.family == AF_PACKET) &&
        fnmatch(filter.label, RTA_DATA(tb[IFLA_IFNAME]), 0))
        return 0;

    if (tb[IFLA_GROUP]) {
        int group = rta_getattr_u32(tb[IFLA_GROUP]);

        if (filter.group != -1 && group != filter.group)
            return -1;
    }

    if (tb[IFLA_MASTER]) {
        int master = rta_getattr_u32(tb[IFLA_MASTER]);

        if (filter.master > 0 && master != filter.master)
            return -1;
    } else if (filter.master > 0)
        return -1;

    if (filter.kind && match_link_kind(tb, filter.kind, 0))
        return -1;

    if (filter.slave_kind && match_link_kind(tb, filter.slave_kind, 1))
        return -1;

    if (n->nlmsg_type == RTM_DELLINK)
        print_bool(PRINT_ANY, "deleted", "Deleted ", true);

    print_int(PRINT_ANY, "ifindex", "%d: ", ifi->ifi_index);
    if (tb[IFLA_IFNAME]) {
        print_color_string(PRINT_ANY,
                           COLOR_IFNAME,
                           "ifname", "%s",
                           rta_getattr_str(tb[IFLA_IFNAME]));
    } else {
        print_null(PRINT_JSON, "ifname", NULL, NULL);
        print_color_null(PRINT_FP, COLOR_IFNAME,
                         "ifname", "%s", "<nil>");
    }

    if (tb[IFLA_LINK]) {
        int iflink = rta_getattr_u32(tb[IFLA_LINK]);

        if (iflink == 0)
            print_null(PRINT_ANY, "link", "@%s: ", "NONE");
        else {
            if (tb[IFLA_LINK_NETNSID])
                print_int(PRINT_ANY,
                          "link_index", "@if%d: ", iflink);
            else {
                SPRINT_BUF(b1);

                print_string(PRINT_ANY,
                             "link",
                             "@%s: ",
                             ll_idx_n2a(iflink, b1));
                m_flag = ll_index_to_flags(iflink);
                m_flag = !(m_flag & IFF_UP);
            }
        }
    } else {
        print_string(PRINT_FP, NULL, ": ", NULL);
    }
    print_link_flags(fp, ifi->ifi_flags, m_flag);

    if (tb[IFLA_MTU])
        print_int(PRINT_ANY,
                  "mtu", "mtu %u ",
                  rta_getattr_u32(tb[IFLA_MTU]));
    if (tb[IFLA_XDP])
        xdp_dump(fp, tb[IFLA_XDP], do_link, false);
    if (tb[IFLA_QDISC])
        print_string(PRINT_ANY,
                     "qdisc",
                     "qdisc %s ",
                     rta_getattr_str(tb[IFLA_QDISC]));
    if (tb[IFLA_MASTER]) {
        SPRINT_BUF(b1);

        print_string(PRINT_ANY,
                     "master",
                     "master %s ",
                     ll_idx_n2a(rta_getattr_u32(tb[IFLA_MASTER]), b1));
    }

    if (tb[IFLA_OPERSTATE])
        print_operstate(fp, rta_getattr_u8(tb[IFLA_OPERSTATE]));

    if (do_link && tb[IFLA_LINKMODE])
        print_linkmode(fp, tb[IFLA_LINKMODE]);

    if (tb[IFLA_GROUP]) {
        SPRINT_BUF(b1);
        int group = rta_getattr_u32(tb[IFLA_GROUP]);

        print_string(PRINT_ANY,
                     "group",
                     "group %s ",
                     rtnl_group_n2a(group, b1, sizeof(b1)));
    }

    if (filter.showqueue)
        print_queuelen(fp, tb);

    if (tb[IFLA_EVENT])
        print_link_event(fp, rta_getattr_u32(tb[IFLA_EVENT]));

    if (!filter.family || filter.family == AF_PACKET || show_details) {
        SPRINT_BUF(b1);

        print_string(PRINT_FP, NULL, "%s", _SL_);
        print_string(PRINT_ANY,
                     "link_type",
                     "    link/%s ",
                     ll_type_n2a(ifi->ifi_type, b1, sizeof(b1)));
        if (tb[IFLA_ADDRESS]) {
            print_color_string(PRINT_ANY,
                               COLOR_MAC,
                               "address",
                               "%s",
                               ll_addr_n2a(RTA_DATA(tb[IFLA_ADDRESS]),
                                           RTA_PAYLOAD(tb[IFLA_ADDRESS]),
                                           ifi->ifi_type,
                                           b1, sizeof(b1)));
        }
        if (tb[IFLA_BROADCAST]) {
            if (ifi->ifi_flags & IFF_POINTOPOINT) {
                print_string(PRINT_FP, NULL, " peer ", NULL);
                print_bool(PRINT_JSON,
                           "link_pointtopoint", NULL, true);
            } else {
                print_string(PRINT_FP, NULL, " brd ", NULL);
            }
            print_color_string(PRINT_ANY,
                               COLOR_MAC,
                               "broadcast",
                               "%s",
                               ll_addr_n2a(RTA_DATA(tb[IFLA_BROADCAST]),
                                           RTA_PAYLOAD(tb[IFLA_BROADCAST]),
                                           ifi->ifi_type,
                                           b1, sizeof(b1)));
        }
    }

    if (tb[IFLA_LINK_NETNSID]) {
        int id = rta_getattr_u32(tb[IFLA_LINK_NETNSID]);

        if (is_json_context()) {
            print_int(PRINT_JSON, "link_netnsid", NULL, id);
        } else {
            if (id >= 0)
                print_int(PRINT_FP, NULL,
                          " link-netnsid %d", id);
            else
                print_string(PRINT_FP, NULL,
                             " link-netnsid %s", "unknown");
        }
    }

    if (tb[IFLA_PROTO_DOWN]) {
        if (rta_getattr_u8(tb[IFLA_PROTO_DOWN]))
            print_bool(PRINT_ANY,
                       "proto_down", " protodown on ", true);
    }

    if (show_details) {
        if (tb[IFLA_PROMISCUITY])
            print_uint(PRINT_ANY,
                       "promiscuity",
                       " promiscuity %u ",
                       rta_getattr_u32(tb[IFLA_PROMISCUITY]));

        if (tb[IFLA_LINKINFO])
            print_linktype(fp, tb[IFLA_LINKINFO]);

        if (do_link && tb[IFLA_AF_SPEC])
            print_af_spec(fp, tb[IFLA_AF_SPEC]);

        if (tb[IFLA_NUM_TX_QUEUES])
            print_uint(PRINT_ANY,
                       "num_tx_queues",
                       "numtxqueues %u ",
                       rta_getattr_u32(tb[IFLA_NUM_TX_QUEUES]));

        if (tb[IFLA_NUM_RX_QUEUES])
            print_uint(PRINT_ANY,
                       "num_rx_queues",
                       "numrxqueues %u ",
                       rta_getattr_u32(tb[IFLA_NUM_RX_QUEUES]));

        if (tb[IFLA_GSO_MAX_SIZE])
            print_uint(PRINT_ANY,
                       "gso_max_size",
                       "gso_max_size %u ",
                       rta_getattr_u32(tb[IFLA_GSO_MAX_SIZE]));

        if (tb[IFLA_GSO_MAX_SEGS])
            print_uint(PRINT_ANY,
                       "gso_max_segs",
                       "gso_max_segs %u ",
                       rta_getattr_u32(tb[IFLA_GSO_MAX_SEGS]));

        if (tb[IFLA_PHYS_PORT_NAME])
            print_string(PRINT_ANY,
                         "phys_port_name",
                         "portname %s ",
                         rta_getattr_str(tb[IFLA_PHYS_PORT_NAME]));

        if (tb[IFLA_PHYS_PORT_ID]) {
            SPRINT_BUF(b1);
            print_string(PRINT_ANY,
                         "phys_port_id",
                         "portid %s ",
                         hexstring_n2a(
                                 RTA_DATA(tb[IFLA_PHYS_PORT_ID]),
                                 RTA_PAYLOAD(tb[IFLA_PHYS_PORT_ID]),
                                 b1, sizeof(b1)));
        }

        if (tb[IFLA_PHYS_SWITCH_ID]) {
            SPRINT_BUF(b1);
            print_string(PRINT_ANY,
                         "phys_switch_id",
                         "switchid %s ",
                         hexstring_n2a(RTA_DATA(tb[IFLA_PHYS_SWITCH_ID]),
                                       RTA_PAYLOAD(tb[IFLA_PHYS_SWITCH_ID]),
                                       b1, sizeof(b1)));
        }
    }

    if ((do_link || show_details) && tb[IFLA_IFALIAS]) {
        print_string(PRINT_FP, NULL, "%s    ", _SL_);
        print_string(PRINT_ANY,
                     "ifalias",
                     "alias %s",
                     rta_getattr_str(tb[IFLA_IFALIAS]));
    }

    if ((do_link || show_details) && tb[IFLA_XDP])
        xdp_dump(fp, tb[IFLA_XDP], true, true);

    if (do_link && show_stats) {
        print_string(PRINT_FP, NULL, "%s", _SL_);
        __print_link_stats(fp, tb);
    }

    if ((do_link || show_details) && tb[IFLA_VFINFO_LIST] && tb[IFLA_NUM_VF]) {
        struct rtattr *i, *vflist = tb[IFLA_VFINFO_LIST];
        int rem = RTA_PAYLOAD(vflist);

        open_json_array(PRINT_JSON, "vfinfo_list");
        for (i = RTA_DATA(vflist); RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
            open_json_object(NULL);
            print_vfinfo(fp, i);
            close_json_object();
        }
        close_json_array(PRINT_JSON, NULL);
    }

    print_string(PRINT_FP, NULL, "\n", NULL);
    fflush(fp);
    return 1;
}

int print_linkinfo_brief(const struct sockaddr_nl *who,
                         struct nlmsghdr *n, void *arg,
                         struct link_filter *pfilter) {
    FILE *fp = (FILE *) arg;
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct rtattr *tb[IFLA_MAX + 1];
    int len = n->nlmsg_len;
    const char *name;
    char buf[32] = {0,};
    unsigned int m_flag = 0;

    if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
        return -1;

    len -= NLMSG_LENGTH(sizeof(*ifi));
    if (len < 0)
        return -1;

    if (!pfilter)
        pfilter = &filter;

    if (pfilter->ifindex && ifi->ifi_index != pfilter->ifindex)
        return -1;
    if (pfilter->up && !(ifi->ifi_flags & IFF_UP))
        return -1;

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
    if (tb[IFLA_IFNAME] == NULL) {
        fprintf(stderr, "BUG: device with ifindex %d has nil ifname\n", ifi->ifi_index);
        name = "<nil>";
    } else {
        name = rta_getattr_str(tb[IFLA_IFNAME]);
    }

    if (pfilter->label &&
        (!pfilter->family || pfilter->family == AF_PACKET) &&
        fnmatch(pfilter->label, RTA_DATA(tb[IFLA_IFNAME]), 0))
        return -1;

    if (tb[IFLA_GROUP]) {
        int group = rta_getattr_u32(tb[IFLA_GROUP]);

        if (pfilter->group != -1 && group != pfilter->group)
            return -1;
    }

    if (tb[IFLA_MASTER]) {
        int master = rta_getattr_u32(tb[IFLA_MASTER]);

        if (pfilter->master > 0 && master != pfilter->master)
            return -1;
    } else if (pfilter->master > 0)
        return -1;

    if (pfilter->kind && match_link_kind(tb, pfilter->kind, 0))
        return -1;

    if (pfilter->slave_kind && match_link_kind(tb, pfilter->slave_kind, 1))
        return -1;

    if (n->nlmsg_type == RTM_DELLINK)
        print_bool(PRINT_ANY, "deleted", "Deleted ", true);

    if (tb[IFLA_LINK]) {
        SPRINT_BUF(b1);
        int iflink = rta_getattr_u32(tb[IFLA_LINK]);

        if (iflink == 0) {
            snprintf(buf, sizeof(buf), "%s@NONE", name);
            print_null(PRINT_JSON, "link", NULL, NULL);
        } else {
            const char *link = ll_idx_n2a(iflink, b1);

            print_string(PRINT_JSON, "link", NULL, link);
            snprintf(buf, sizeof(buf), "%s@%s", name, link);
            m_flag = ll_index_to_flags(iflink);
            m_flag = !(m_flag & IFF_UP);
        }
    } else
        snprintf(buf, sizeof(buf), "%s", name);

    print_string(PRINT_FP, NULL, "%-16s ", buf);
    print_string(PRINT_JSON, "ifname", NULL, name);

    if (tb[IFLA_OPERSTATE])
        print_operstate(fp, rta_getattr_u8(tb[IFLA_OPERSTATE]));

    if (pfilter->family == AF_PACKET) {
        SPRINT_BUF(b1);

        if (tb[IFLA_ADDRESS]) {
            print_color_string(PRINT_ANY, COLOR_MAC,
                               "address", "%s ",
                               ll_addr_n2a(
                                       RTA_DATA(tb[IFLA_ADDRESS]),
                                       RTA_PAYLOAD(tb[IFLA_ADDRESS]),
                                       ifi->ifi_type,
                                       b1, sizeof(b1)));
        }
    }

    if (pfilter->family == AF_PACKET) {
        print_link_flags(fp, ifi->ifi_flags, m_flag);
        print_string(PRINT_FP, NULL, "%s", "\n");
    }
    fflush(fp);
    return 0;
}

int do_ipaddr(int argc, char **argv) {



//    if (matches(*argv, "list") == 0 || matches(*argv, "show") == 0
//        || matches(*argv, "lst") == 0)
    return ipaddr_list_flush_or_save(1, argv, IPADD_LIST);

//    fprintf(stderr, "Command \"%s\" is unknown, try \"ip address help\".\n", *argv);
//    exit(-1);
}

