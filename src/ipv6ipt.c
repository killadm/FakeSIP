/*
 * ipv6ipt.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
 *
 * Copyright (C) 2025  MikeWang000000
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include "ipv6ipt.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "filter.h"
#include "globvar.h"
#include "logging.h"
#include "process.h"

static int ipv6_net_to_str(const struct fs_ipv6_net *net, char *buf,
                           size_t buf_size)
{
    char addr_buf[INET6_ADDRSTRLEN];
    const char *res;
    int len;

    res = inet_ntop(AF_INET6, &net->addr, addr_buf, sizeof(addr_buf));
    if (!res) {
        E("ERROR: inet_ntop(): %s", strerror(errno));
        return -1;
    }

    len = snprintf(buf, buf_size, "%s/%u", addr_buf,
                   (unsigned int) net->prefix);
    if (len < 0 || (size_t) len >= buf_size) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    return 0;
}


static int port_range_to_str(const struct fs_port_range *port, char *buf,
                             size_t buf_size)
{
    int len;

    if (port->start == port->end) {
        len = snprintf(buf, buf_size, "%u", (unsigned int) port->start);
    } else {
        len = snprintf(buf, buf_size, "%u:%u", (unsigned int) port->start,
                       (unsigned int) port->end);
    }

    if (len < 0 || (size_t) len >= buf_size) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    return 0;
}


static int run_ipt6_cmd(char **cmd)
{
    int res;

    res = fs_execute_command(cmd, 0, NULL);
    if (res < 0) {
        E(T(fs_execute_command));
        return -1;
    }

    return 0;
}


static int ipt6_add_queue_rule(const char *chain, const char *nfqnum_str)
{
    char *queue_cmd[] = {"ip6tables",
                         "-w",
                         "-t",
                         "mangle",
                         "-A",
                         (char *) chain,
                         "-p",
                         "udp",
                         "-m",
                         "connbytes",
                         "--connbytes",
                         "1:5",
                         "--connbytes-dir",
                         "both",
                         "--connbytes-mode",
                         "packets",
                         "-j",
                         "NFQUEUE",
                         "--queue-bypass",
                         "--queue-num",
                         (char *) nfqnum_str,
                         NULL};

    return run_ipt6_cmd(queue_cmd);
}


static int ipt6_filter_setup(const char *nfqnum_str)
{
    size_t i;
    int ip_allow;
    char ipstr[INET6_ADDRSTRLEN + 5], portstr[16];
    char *deny_src_ip_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                               "-A",        "FAKESIP_R", "-s", ipstr,
                               "-j",        "RETURN",    NULL};
    char *deny_dst_ip_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                               "-A",        "FAKESIP_R", "-d", ipstr,
                               "-j",        "RETURN",    NULL};
    char *deny_sport_cmd[] = {"ip6tables", "-w",     "-t",  "mangle",  "-A",
                              "FAKESIP_R", "-p",     "udp", "--sport", portstr,
                              "-j",        "RETURN", NULL};
    char *deny_dport_cmd[] = {"ip6tables", "-w",     "-t",  "mangle",  "-A",
                              "FAKESIP_R", "-p",     "udp", "--dport", portstr,
                              "-j",        "RETURN", NULL};
    char *allow_src_ip_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                                "-A",        "FAKESIP_R", "-s", ipstr,
                                "-j",        "FAKESIP_A", NULL};
    char *allow_dst_ip_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                                "-A",        "FAKESIP_R", "-d", ipstr,
                                "-j",        "FAKESIP_A", NULL};
    char *return_r_cmd[] = {"ip6tables", "-w", "-t",     "mangle", "-A",
                            "FAKESIP_R", "-j", "RETURN", NULL};
    char *jump_a_cmd[] = {"ip6tables", "-w", "-t",        "mangle", "-A",
                          "FAKESIP_R", "-j", "FAKESIP_A", NULL};
    char *allow_sport_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                               "-A",        "FAKESIP_A", "-p", "udp",
                               "--sport",   portstr,     "-j", "FAKESIP_Q",
                               NULL};
    char *allow_dport_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                               "-A",        "FAKESIP_A", "-p", "udp",
                               "--dport",   portstr,     "-j", "FAKESIP_Q",
                               NULL};
    char *return_a_cmd[] = {"ip6tables", "-w", "-t",     "mangle", "-A",
                            "FAKESIP_A", "-j", "RETURN", NULL};
    char *jump_q_cmd[] = {"ip6tables", "-w", "-t",        "mangle", "-A",
                          "FAKESIP_A", "-j", "FAKESIP_Q", NULL};

    if (!fs_filter_has_rules()) {
        return ipt6_add_queue_rule("FAKESIP_R", nfqnum_str);
    }

    for (i = 0; i < g_ctx.filter.deny6_cnt; i++) {
        if (ipv6_net_to_str(&g_ctx.filter.deny6[i], ipstr, sizeof(ipstr)) <
                0 ||
            run_ipt6_cmd(deny_src_ip_cmd) < 0 ||
            run_ipt6_cmd(deny_dst_ip_cmd) < 0) {
            return -1;
        }
    }

    for (i = 0; i < g_ctx.filter.deny_ports_cnt; i++) {
        if (port_range_to_str(&g_ctx.filter.deny_ports[i], portstr,
                              sizeof(portstr)) < 0 ||
            run_ipt6_cmd(deny_sport_cmd) < 0 ||
            run_ipt6_cmd(deny_dport_cmd) < 0) {
            return -1;
        }
    }

    ip_allow = g_ctx.filter.allow4_cnt || g_ctx.filter.allow6_cnt;
    if (ip_allow) {
        for (i = 0; i < g_ctx.filter.allow6_cnt; i++) {
            if (ipv6_net_to_str(&g_ctx.filter.allow6[i], ipstr,
                                sizeof(ipstr)) < 0 ||
                run_ipt6_cmd(allow_src_ip_cmd) < 0 ||
                run_ipt6_cmd(allow_dst_ip_cmd) < 0) {
                return -1;
            }
        }
        if (run_ipt6_cmd(return_r_cmd) < 0) {
            return -1;
        }
    } else if (run_ipt6_cmd(jump_a_cmd) < 0) {
        return -1;
    }

    if (g_ctx.filter.allow_ports_cnt) {
        for (i = 0; i < g_ctx.filter.allow_ports_cnt; i++) {
            if (port_range_to_str(&g_ctx.filter.allow_ports[i], portstr,
                                  sizeof(portstr)) < 0 ||
                run_ipt6_cmd(allow_sport_cmd) < 0 ||
                run_ipt6_cmd(allow_dport_cmd) < 0) {
                return -1;
            }
        }
        if (run_ipt6_cmd(return_a_cmd) < 0) {
            return -1;
        }
    } else if (run_ipt6_cmd(jump_q_cmd) < 0) {
        return -1;
    }

    return ipt6_add_queue_rule("FAKESIP_Q", nfqnum_str);
}

static int ipt6_iface_setup(void)
{
    char iface_str[IFNAMSIZ];
    size_t i;
    int res;
    char *ipt_alliface_src_cmd[] = {"ip6tables", "-w",        "-t",
                                    "mangle",    "-A",        "FAKESIP_S",
                                    "-j",        "FAKESIP_R", NULL};

    char *ipt_alliface_dst_cmd[] = {"ip6tables", "-w",        "-t",
                                    "mangle",    "-A",        "FAKESIP_D",
                                    "-j",        "FAKESIP_R", NULL};

    char *ipt_iface_src_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                                 "-A",        "FAKESIP_S", "-i", iface_str,
                                 "-j",        "FAKESIP_R", NULL};

    char *ipt_iface_dst_cmd[] = {"ip6tables", "-w",        "-t", "mangle",
                                 "-A",        "FAKESIP_D", "-o", iface_str,
                                 "-j",        "FAKESIP_R", NULL};

    if (g_ctx.alliface) {
        res = fs_execute_command(ipt_alliface_src_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }
        res = fs_execute_command(ipt_alliface_dst_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }
        return 0;
    }

    for (i = 0; g_ctx.iface[i]; i++) {
        res = snprintf(iface_str, sizeof(iface_str), "%s", g_ctx.iface[i]);
        if (res < 0 || (size_t) res >= sizeof(iface_str)) {
            E("ERROR: snprintf(): %s", "failure");
            return -1;
        }

        res = fs_execute_command(ipt_iface_src_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }

        res = fs_execute_command(ipt_iface_dst_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }
    }
    return 0;
}


int fs_ipt6_setup(void)
{
    char xmark_str[64], nfqnum_str[32];
    size_t i, ipt_cmds_cnt;
    int res;
    char *ipt_cmds[][32] = {
        {"ip6tables", "-w", "-t", "mangle", "-N", "FAKESIP_S", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-N", "FAKESIP_D", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-I", "PREROUTING", "-j",
         "FAKESIP_S", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-I", "POSTROUTING", "-j",
         "FAKESIP_D", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-N", "FAKESIP_R", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-N", "FAKESIP_A", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-N", "FAKESIP_Q", NULL},

        /*
            drop time-exceeded ICMP packets
        */
        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKESIP_S", "-p",
         "ipv6-icmp", "--icmpv6-type", "time-exceeded", "-j", "DROP", NULL},

        /*
            exclude non-GUA IPv6 addresses (from source)
        */
        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKESIP_S", "!", "-s",
         "2000::/3", "-j", "RETURN", NULL},

        /*
            exclude non-GUA IPv6 addresses (to destination)
        */
        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKESIP_D", "!", "-d",
         "2000::/3", "-j", "RETURN", NULL},

        /*
            exclude marked packets
        */
        {"ip6tables", "-w", "-t", "mangle", "-A", "FAKESIP_R", "-m", "mark",
         "--mark", xmark_str, "-j", "RETURN", NULL}};

    ipt_cmds_cnt = sizeof(ipt_cmds) / sizeof(*ipt_cmds);

    res = snprintf(xmark_str, sizeof(xmark_str), "%" PRIu32 "/%" PRIu32,
                   g_ctx.fwmark, g_ctx.fwmask);
    if (res < 0 || (size_t) res >= sizeof(xmark_str)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    res = snprintf(nfqnum_str, sizeof(nfqnum_str), "%" PRIu32, g_ctx.nfqnum);
    if (res < 0 || (size_t) res >= sizeof(nfqnum_str)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    fs_ipt6_cleanup();

    for (i = 0; i < ipt_cmds_cnt; i++) {
        res = fs_execute_command(ipt_cmds[i], 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }
    }

    res = ipt6_filter_setup(nfqnum_str);
    if (res < 0) {
        E(T(ipt6_filter_setup));
        return -1;
    }

    res = ipt6_iface_setup();
    if (res < 0) {
        E(T(ipt6_iface_setup));
        return -1;
    }

    return 0;
}


void fs_ipt6_cleanup(void)
{
    size_t i, cnt;
    char *ipt_cmds[][32] = {
        {"ip6tables", "-w", "-t", "mangle", "-F", "FAKESIP_Q", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-F", "FAKESIP_A", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-F", "FAKESIP_R", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-F", "FAKESIP_S", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-F", "FAKESIP_D", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-D", "PREROUTING", "-j",
         "FAKESIP_S", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-D", "POSTROUTING", "-j",
         "FAKESIP_D", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-X", "FAKESIP_R", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-X", "FAKESIP_A", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-X", "FAKESIP_Q", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-X", "FAKESIP_S", NULL},

        {"ip6tables", "-w", "-t", "mangle", "-X", "FAKESIP_D", NULL}};

    cnt = sizeof(ipt_cmds) / sizeof(*ipt_cmds);
    for (i = 0; i < cnt; i++) {
        fs_execute_command(ipt_cmds[i], 1, NULL);
    }
}
