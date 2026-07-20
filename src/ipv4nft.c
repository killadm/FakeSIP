/*
 * ipv4nft.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "ipv4nft.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "filter.h"
#include "globvar.h"
#include "logging.h"
#include "process.h"

struct strbuf {
    char *data;
    size_t len;
    size_t cap;
};

static int sb_append(struct strbuf *sb, const char *fmt, ...)
{
    int len;
    va_list args;
    char tmp[512], *new_data;
    size_t new_len, new_cap;

    va_start(args, fmt);
    len = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);

    if (len < 0 || (size_t) len >= sizeof(tmp)) {
        E("ERROR: vsnprintf(): %s", "failure");
        return -1;
    }

    new_len = sb->len + len;
    if (new_len + 1 > sb->cap) {
        new_cap = sb->cap ? sb->cap : 4096;
        while (new_len + 1 > new_cap) {
            new_cap *= 2;
        }

        new_data = realloc(sb->data, new_cap);
        if (!new_data) {
            E("ERROR: realloc(): %s", strerror(errno));
            return -1;
        }

        sb->data = new_data;
        sb->cap = new_cap;
    }

    memcpy(sb->data + sb->len, tmp, len + 1);
    sb->len = new_len;

    return 0;
}


static int ipv4_net_to_str(const struct fs_ipv4_net *net, char *buf,
                           size_t buf_size)
{
    struct in_addr addr;
    char addr_buf[INET_ADDRSTRLEN];
    const char *res;
    int len;

    addr.s_addr = htonl(net->addr);
    res = inet_ntop(AF_INET, &addr, addr_buf, sizeof(addr_buf));
    if (!res) {
        E("ERROR: inet_ntop(): %s", strerror(errno));
        return -1;
    }

    if (net->prefix == 32) {
        len = snprintf(buf, buf_size, "%s", addr_buf);
    } else {
        len = snprintf(buf, buf_size, "%s/%u", addr_buf,
                       (unsigned int) net->prefix);
    }

    if (len < 0 || (size_t) len >= buf_size) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    return 0;
}


static int append_ipv4_set(struct strbuf *sb, const char *name,
                           const struct fs_ipv4_net *nets, size_t cnt)
{
    size_t i;
    char net_buf[INET_ADDRSTRLEN + 4];

    if (!cnt) {
        return 0;
    }

    if (sb_append(sb, "    set %s {\n", name) < 0 ||
        sb_append(sb, "        type ipv4_addr;\n") < 0 ||
        sb_append(sb, "        flags interval;\n") < 0 ||
        sb_append(sb, "        elements = { ") < 0) {
        return -1;
    }

    for (i = 0; i < cnt; i++) {
        if (ipv4_net_to_str(&nets[i], net_buf, sizeof(net_buf)) < 0) {
            return -1;
        }
        if (sb_append(sb, "%s%s", i ? ", " : "", net_buf) < 0) {
            return -1;
        }
    }

    return sb_append(sb, " };\n    }\n\n");
}


static int append_port_set(struct strbuf *sb, const char *name,
                           const struct fs_port_range *ports, size_t cnt)
{
    size_t i;

    if (!cnt) {
        return 0;
    }

    if (sb_append(sb, "    set %s {\n", name) < 0 ||
        sb_append(sb, "        type inet_service;\n") < 0 ||
        sb_append(sb, "        flags interval;\n") < 0 ||
        sb_append(sb, "        elements = { ") < 0) {
        return -1;
    }

    for (i = 0; i < cnt; i++) {
        if (ports[i].start == ports[i].end) {
            if (sb_append(sb, "%s%u", i ? ", " : "",
                          (unsigned int) ports[i].start) < 0) {
                return -1;
            }
        } else {
            if (sb_append(sb, "%s%u-%u", i ? ", " : "",
                          (unsigned int) ports[i].start,
                          (unsigned int) ports[i].end) < 0) {
                return -1;
            }
        }
    }

    return sb_append(sb, " };\n    }\n\n");
}


static int append_filter_sets(struct strbuf *sb)
{
    if (append_ipv4_set(sb, "fs_allow_ip", g_ctx.filter.allow4,
                        g_ctx.filter.allow4_cnt) < 0 ||
        append_ipv4_set(sb, "fs_deny_ip", g_ctx.filter.deny4,
                        g_ctx.filter.deny4_cnt) < 0 ||
        append_port_set(sb, "fs_allow_port", g_ctx.filter.allow_ports,
                        g_ctx.filter.allow_ports_cnt) < 0 ||
        append_port_set(sb, "fs_deny_port", g_ctx.filter.deny_ports,
                        g_ctx.filter.deny_ports_cnt) < 0) {
        return -1;
    }

    return 0;
}


static int append_queue_rule(struct strbuf *sb)
{
    return sb_append(sb,
                     "        meta l4proto udp ct packets 1-5 queue num %"
                     PRIu32 " bypass;\n",
                     g_ctx.nfqnum);
}


static int append_filter_chains(struct strbuf *sb)
{
    int ip_allow;

    if (sb_append(sb, "    chain fs_rules {\n") < 0 ||
        sb_append(sb, "        meta mark and %" PRIu32 " == %" PRIu32
                      " return;\n",
                  g_ctx.fwmask, g_ctx.fwmark) < 0) {
        return -1;
    }

    if (!fs_filter_has_rules()) {
        if (append_queue_rule(sb) < 0) {
            return -1;
        }
        return sb_append(sb, "    }\n");
    }

    if (g_ctx.filter.deny4_cnt) {
        if (sb_append(sb, "        ip saddr @fs_deny_ip return;\n") < 0 ||
            sb_append(sb, "        ip daddr @fs_deny_ip return;\n") < 0) {
            return -1;
        }
    }

    if (g_ctx.filter.deny_ports_cnt) {
        if (sb_append(sb, "        udp sport @fs_deny_port return;\n") < 0 ||
            sb_append(sb, "        udp dport @fs_deny_port return;\n") < 0) {
            return -1;
        }
    }

    ip_allow = g_ctx.filter.allow4_cnt || g_ctx.filter.allow6_cnt;
    if (ip_allow) {
        if (g_ctx.filter.allow4_cnt) {
            if (sb_append(sb, "        ip saddr @fs_allow_ip jump fs_allow;\n") <
                    0 ||
                sb_append(sb, "        ip daddr @fs_allow_ip jump fs_allow;\n") <
                    0) {
                return -1;
            }
        }
        if (sb_append(sb, "        return;\n") < 0) {
            return -1;
        }
    } else if (sb_append(sb, "        jump fs_allow;\n") < 0) {
        return -1;
    }

    if (sb_append(sb, "    }\n\n") < 0 ||
        sb_append(sb, "    chain fs_allow {\n") < 0) {
        return -1;
    }

    if (g_ctx.filter.allow_ports_cnt) {
        if (sb_append(sb, "        udp sport @fs_allow_port jump fs_queue;\n") <
                0 ||
            sb_append(sb, "        udp dport @fs_allow_port jump fs_queue;\n") <
                0 ||
            sb_append(sb, "        return;\n") < 0) {
            return -1;
        }
    } else if (sb_append(sb, "        jump fs_queue;\n") < 0) {
        return -1;
    }

    if (sb_append(sb, "    }\n\n") < 0 ||
        sb_append(sb, "    chain fs_queue {\n") < 0 ||
        append_queue_rule(sb) < 0 ||
        sb_append(sb, "    }\n") < 0) {
        return -1;
    }

    return 0;
}


static int nft4_iface_setup(void)
{
    char nftstr[120];
    size_t i;
    int res;
    char *nft_iface_cmd[] = {"nft", nftstr, NULL};

    if (g_ctx.alliface) {
        res = snprintf(nftstr, sizeof(nftstr),
                       "add rule ip fakesip fs_prerouting jump fs_rules");
        if (res < 0 || (size_t) res >= sizeof(nftstr)) {
            E("ERROR: snprintf(): %s", "failure");
            return -1;
        }
        res = fs_execute_command(nft_iface_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }

        res = snprintf(nftstr, sizeof(nftstr),
                       "add rule ip fakesip fs_postrouting jump fs_rules");
        if (res < 0 || (size_t) res >= sizeof(nftstr)) {
            E("ERROR: snprintf(): %s", "failure");
            return -1;
        }
        res = fs_execute_command(nft_iface_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }

        return 0;
    }

    for (i = 0; g_ctx.iface[i]; i++) {
        res = snprintf(nftstr, sizeof(nftstr),
                       "add rule ip fakesip fs_prerouting iifname \"%s\" "
                       "jump fs_rules",
                       g_ctx.iface[i]);
        if (res < 0 || (size_t) res >= sizeof(nftstr)) {
            E("ERROR: snprintf(): %s", "failure");
            return -1;
        }
        res = fs_execute_command(nft_iface_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }

        res = snprintf(nftstr, sizeof(nftstr),
                       "add rule ip fakesip fs_postrouting oifname \"%s\" "
                       "jump fs_rules",
                       g_ctx.iface[i]);
        if (res < 0 || (size_t) res >= sizeof(nftstr)) {
            E("ERROR: snprintf(): %s", "failure");
            return -1;
        }
        res = fs_execute_command(nft_iface_cmd, 0, NULL);
        if (res < 0) {
            E(T(fs_execute_command));
            return -1;
        }
    }
    return 0;
}


int fs_nft4_setup(void)
{
    int res;
    char *nft_cmd[] = {"nft", "-f", "-", NULL};
    struct strbuf nft_conf;

    memset(&nft_conf, 0, sizeof(nft_conf));

    fs_nft4_cleanup();

    if (sb_append(&nft_conf, "table ip fakesip {\n") < 0 ||
        append_filter_sets(&nft_conf) < 0 ||
        sb_append(&nft_conf,
                  "    chain fs_prerouting {\n"
                  "        type filter hook prerouting priority mangle - 5;\n"
                  "        policy accept;\n"
                  "        icmp type time-exceeded counter drop;\n"
                  "        ip saddr 0.0.0.0/8      return;\n"
                  "        ip saddr 10.0.0.0/8     return;\n"
                  "        ip saddr 100.64.0.0/10  return;\n"
                  "        ip saddr 127.0.0.0/8    return;\n"
                  "        ip saddr 169.254.0.0/16 return;\n"
                  "        ip saddr 172.16.0.0/12  return;\n"
                  "        ip saddr 192.168.0.0/16 return;\n"
                  "        ip saddr 224.0.0.0/3    return;\n"
                  "    }\n"
                  "\n"
                  "    chain fs_postrouting {\n"
                  "        type filter hook postrouting priority mangle - 5;\n"
                  "        policy accept;\n"
                  "        ip daddr 0.0.0.0/8      return;\n"
                  "        ip daddr 10.0.0.0/8     return;\n"
                  "        ip daddr 100.64.0.0/10  return;\n"
                  "        ip daddr 127.0.0.0/8    return;\n"
                  "        ip daddr 169.254.0.0/16 return;\n"
                  "        ip daddr 172.16.0.0/12  return;\n"
                  "        ip daddr 192.168.0.0/16 return;\n"
                  "        ip daddr 224.0.0.0/3    return;\n"
                  "    }\n"
                  "\n") < 0 ||
        append_filter_chains(&nft_conf) < 0 ||
        sb_append(&nft_conf, "}\n") < 0) {
        free(nft_conf.data);
        return -1;
    }

    res = fs_execute_command(nft_cmd, 0, nft_conf.data);
    free(nft_conf.data);
    if (res < 0) {
        E(T(fs_execute_command));
        return -1;
    }

    res = nft4_iface_setup();
    if (res < 0) {
        E(T(nft4_iface_setup));
        return -1;
    }

    return 0;
}


void fs_nft4_cleanup(void)
{
    char *nft_delete_cmd[] = {"nft", "delete table ip fakesip", NULL};

    fs_execute_command(nft_delete_cmd, 1, NULL);
}
