/*
 * filter.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "filter.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "globvar.h"
#include "logging.h"

enum filter_action {
    FS_FILTER_ALLOW = 1,
    FS_FILTER_DENY
};

struct fs_ipv4_range {
    uint32_t start;
    uint32_t end;
};

struct fs_ipv6_range {
    struct in6_addr start;
    struct in6_addr end;
};

static size_t allow4_cap, deny4_cap, allow6_cap, deny6_cap;
static size_t allow_ports_cap, deny_ports_cap;
static int filter_has_rules, filter_has_ip_allow;
static struct fs_ipv4_range *allow4_ranges, *deny4_ranges;
static struct fs_ipv6_range *allow6_ranges, *deny6_ranges;
static size_t allow4_ranges_cnt, deny4_ranges_cnt;
static size_t allow6_ranges_cnt, deny6_ranges_cnt;

static int has_ip_allow(void)
{
    return filter_has_ip_allow;
}


static int filter_counts_have_rules(void)
{
    return g_ctx.filter.allow4_cnt || g_ctx.filter.deny4_cnt ||
           g_ctx.filter.allow6_cnt || g_ctx.filter.deny6_cnt ||
           g_ctx.filter.allow_ports_cnt || g_ctx.filter.deny_ports_cnt;
}


int fs_filter_has_rules(void)
{
    return filter_has_rules;
}


static void *reserve_array(void *arr, size_t *cap, size_t need,
                           size_t elem_size)
{
    void *new_arr;
    size_t new_cap;

    if (need <= *cap) {
        return arr;
    }

    new_cap = *cap ? *cap : 32;
    while (new_cap < need) {
        if (new_cap > (size_t) -1 / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }

    if (new_cap > (size_t) -1 / elem_size) {
        E("ERROR: %s", strerror(ENOMEM));
        return NULL;
    }

    new_arr = realloc(arr, new_cap * elem_size);
    if (!new_arr) {
        E("ERROR: realloc(): %s", strerror(errno));
        return NULL;
    }

    *cap = new_cap;

    return new_arr;
}


static char *trim(char *s)
{
    char *end;

    while (isspace((unsigned char) *s)) {
        s++;
    }

    end = s + strlen(s);
    while (end > s && isspace((unsigned char) end[-1])) {
        *--end = '\0';
    }

    return s;
}


static int parse_uint(const char *s, unsigned long max, unsigned long *val)
{
    char *end;
    unsigned long tmp;

    if (!s[0]) {
        return -1;
    }

    errno = 0;
    tmp = strtoul(s, &end, 10);
    if (errno || *end || tmp > max) {
        return -1;
    }

    *val = tmp;

    return 0;
}


static int append_ipv4(struct fs_ipv4_net **arr, size_t *cnt, size_t *cap,
                       uint32_t addr, uint32_t mask, uint8_t prefix)
{
    struct fs_ipv4_net *new_arr;

    new_arr = reserve_array(*arr, cap, *cnt + 1, sizeof(**arr));
    if (!new_arr) {
        return -1;
    }

    *arr = new_arr;
    (*arr)[*cnt].addr = addr;
    (*arr)[*cnt].mask = mask;
    (*arr)[*cnt].prefix = prefix;
    (*cnt)++;

    return 0;
}


static int append_ipv6(struct fs_ipv6_net **arr, size_t *cnt, size_t *cap,
                       const struct in6_addr *addr, uint8_t prefix)
{
    struct fs_ipv6_net *new_arr;

    new_arr = reserve_array(*arr, cap, *cnt + 1, sizeof(**arr));
    if (!new_arr) {
        return -1;
    }

    *arr = new_arr;
    memcpy(&(*arr)[*cnt].addr, addr, sizeof(*addr));
    (*arr)[*cnt].prefix = prefix;
    (*cnt)++;

    return 0;
}


static int append_port(struct fs_port_range **arr, size_t *cnt, size_t *cap,
                       uint16_t start, uint16_t end)
{
    struct fs_port_range *new_arr;

    new_arr = reserve_array(*arr, cap, *cnt + 1, sizeof(**arr));
    if (!new_arr) {
        return -1;
    }

    *arr = new_arr;
    (*arr)[*cnt].start = start;
    (*arr)[*cnt].end = end;
    (*cnt)++;

    return 0;
}


static void mask_ipv6(struct in6_addr *addr, uint8_t prefix)
{
    size_t i, full;
    uint8_t rem, mask;

    full = prefix / 8;
    rem = prefix % 8;

    if (full < sizeof(addr->s6_addr) && rem) {
        mask = (uint8_t) (0xffU << (8 - rem));
        addr->s6_addr[full] &= mask;
        full++;
    }

    for (i = full; i < sizeof(addr->s6_addr); i++) {
        addr->s6_addr[i] = 0;
    }
}


static int parse_ip(enum filter_action action, const char *value)
{
    char buf[128], *slash;
    unsigned long prefix_ul;
    int has_prefix;
    struct in_addr in4;
    struct in6_addr in6;
    uint32_t addr4, mask4;
    uint8_t prefix;

    if (strlen(value) >= sizeof(buf)) {
        E("ERROR: IP rule is too long: %s", value);
        return -1;
    }
    strcpy(buf, value);

    slash = strchr(buf, '/');
    has_prefix = !!slash;
    if (slash) {
        *slash++ = '\0';
        if (!buf[0] || !slash[0]) {
            E("ERROR: invalid IP rule: %s", value);
            return -1;
        }
    }

    if (inet_pton(AF_INET, buf, &in4) == 1) {
        if (has_prefix) {
            if (parse_uint(slash, 32, &prefix_ul) < 0) {
                E("ERROR: invalid IPv4 prefix: %s", value);
                return -1;
            }
            prefix = prefix_ul;
        } else {
            prefix = 32;
        }

        mask4 = prefix ? UINT32_MAX << (32 - prefix) : 0;
        addr4 = ntohl(in4.s_addr) & mask4;

        if (action == FS_FILTER_ALLOW) {
            return append_ipv4(&g_ctx.filter.allow4, &g_ctx.filter.allow4_cnt,
                               &allow4_cap, addr4, mask4, prefix);
        }

        return append_ipv4(&g_ctx.filter.deny4, &g_ctx.filter.deny4_cnt,
                           &deny4_cap, addr4, mask4, prefix);
    }

    if (inet_pton(AF_INET6, buf, &in6) == 1) {
        if (has_prefix) {
            if (parse_uint(slash, 128, &prefix_ul) < 0) {
                E("ERROR: invalid IPv6 prefix: %s", value);
                return -1;
            }
            prefix = prefix_ul;
        } else {
            prefix = 128;
        }

        mask_ipv6(&in6, prefix);

        if (action == FS_FILTER_ALLOW) {
            return append_ipv6(&g_ctx.filter.allow6, &g_ctx.filter.allow6_cnt,
                               &allow6_cap, &in6, prefix);
        }

        return append_ipv6(&g_ctx.filter.deny6, &g_ctx.filter.deny6_cnt,
                           &deny6_cap, &in6, prefix);
    }

    E("ERROR: invalid IP address: %s", value);

    return -1;
}


static int parse_port(enum filter_action action, const char *value)
{
    char buf[64], *dash;
    unsigned long start_ul, end_ul;
    uint16_t start, end;

    if (strlen(value) >= sizeof(buf)) {
        E("ERROR: port rule is too long: %s", value);
        return -1;
    }
    strcpy(buf, value);

    dash = strchr(buf, '-');
    if (dash) {
        *dash++ = '\0';
        if (!buf[0] || !dash[0]) {
            E("ERROR: invalid port range: %s", value);
            return -1;
        }
    }

    if (parse_uint(buf, UINT16_MAX, &start_ul) < 0) {
        E("ERROR: invalid port: %s", value);
        return -1;
    }

    if (dash) {
        if (parse_uint(dash, UINT16_MAX, &end_ul) < 0) {
            E("ERROR: invalid port range: %s", value);
            return -1;
        }
    } else {
        end_ul = start_ul;
    }

    if (start_ul > end_ul) {
        E("ERROR: invalid port range: %s", value);
        return -1;
    }

    start = start_ul;
    end = end_ul;

    if (action == FS_FILTER_ALLOW) {
        return append_port(&g_ctx.filter.allow_ports,
                           &g_ctx.filter.allow_ports_cnt, &allow_ports_cap,
                           start, end);
    }

    return append_port(&g_ctx.filter.deny_ports, &g_ctx.filter.deny_ports_cnt,
                       &deny_ports_cap, start, end);
}


static int parse_line(char *line)
{
    char *hash, *action_s, *type_s, *value_s, *extra, *saveptr;
    enum filter_action action;

    hash = strchr(line, '#');
    if (hash) {
        *hash = '\0';
    }

    line = trim(line);
    if (!line[0]) {
        return 0;
    }

    saveptr = NULL;
    action_s = strtok_r(line, " \t\r\n", &saveptr);
    type_s = strtok_r(NULL, " \t\r\n", &saveptr);
    value_s = strtok_r(NULL, " \t\r\n", &saveptr);
    extra = strtok_r(NULL, " \t\r\n", &saveptr);

    if (!action_s || !type_s || !value_s || extra) {
        E("ERROR: invalid filter rule");
        return -1;
    }

    if (!strcmp(action_s, "allow")) {
        action = FS_FILTER_ALLOW;
    } else if (!strcmp(action_s, "deny")) {
        action = FS_FILTER_DENY;
    } else {
        E("ERROR: unknown filter action: %s", action_s);
        return -1;
    }

    if (!strcmp(type_s, "ip")) {
        return parse_ip(action, value_s);
    } else if (!strcmp(type_s, "port")) {
        return parse_port(action, value_s);
    }

    E("ERROR: unknown filter type: %s", type_s);

    return -1;
}


static int port_cmp(const void *a, const void *b)
{
    const struct fs_port_range *pa, *pb;

    pa = a;
    pb = b;

    if (pa->start < pb->start) {
        return -1;
    } else if (pa->start > pb->start) {
        return 1;
    } else if (pa->end < pb->end) {
        return -1;
    } else if (pa->end > pb->end) {
        return 1;
    }

    return 0;
}


static void normalize_ports(struct fs_port_range *ports, size_t *cnt)
{
    size_t i, out;

    if (*cnt < 2) {
        return;
    }

    qsort(ports, *cnt, sizeof(*ports), port_cmp);

    out = 0;
    for (i = 1; i < *cnt; i++) {
        if ((unsigned int) ports[i].start <=
            (unsigned int) ports[out].end + 1U) {
            if (ports[i].end > ports[out].end) {
                ports[out].end = ports[i].end;
            }
        } else {
            out++;
            ports[out] = ports[i];
        }
    }

    *cnt = out + 1;
}


static int ipv4_range_cmp(const void *a, const void *b)
{
    const struct fs_ipv4_range *ra, *rb;

    ra = a;
    rb = b;

    if (ra->start < rb->start) {
        return -1;
    } else if (ra->start > rb->start) {
        return 1;
    } else if (ra->end < rb->end) {
        return -1;
    } else if (ra->end > rb->end) {
        return 1;
    }

    return 0;
}


static int build_ipv4_ranges(const struct fs_ipv4_net *nets, size_t nets_cnt,
                             struct fs_ipv4_range **ranges, size_t *ranges_cnt)
{
    struct fs_ipv4_range *new_ranges;
    size_t i, out;

    *ranges = NULL;
    *ranges_cnt = 0;
    if (!nets_cnt) {
        return 0;
    }
    if (nets_cnt > (size_t) -1 / sizeof(*new_ranges)) {
        E("ERROR: %s", strerror(ENOMEM));
        return -1;
    }

    new_ranges = malloc(nets_cnt * sizeof(*new_ranges));
    if (!new_ranges) {
        E("ERROR: malloc(): %s", strerror(errno));
        return -1;
    }

    for (i = 0; i < nets_cnt; i++) {
        new_ranges[i].start = nets[i].addr;
        new_ranges[i].end = nets[i].addr | ~nets[i].mask;
    }

    qsort(new_ranges, nets_cnt, sizeof(*new_ranges), ipv4_range_cmp);

    out = 0;
    for (i = 1; i < nets_cnt; i++) {
        if (new_ranges[out].end == UINT32_MAX ||
            new_ranges[i].start <= new_ranges[out].end + 1U) {
            if (new_ranges[i].end > new_ranges[out].end) {
                new_ranges[out].end = new_ranges[i].end;
            }
        } else {
            out++;
            new_ranges[out] = new_ranges[i];
        }
    }

    *ranges = new_ranges;
    *ranges_cnt = out + 1;

    return 0;
}


static int ipv6_addr_cmp(const struct in6_addr *a, const struct in6_addr *b)
{
    return memcmp(a->s6_addr, b->s6_addr, sizeof(a->s6_addr));
}


static void ipv6_range_end(const struct in6_addr *start, uint8_t prefix,
                           struct in6_addr *end)
{
    size_t i, full;
    uint8_t rem;

    memcpy(end, start, sizeof(*end));
    if (prefix >= 128) {
        return;
    }

    full = prefix / 8;
    rem = prefix % 8;

    if (rem) {
        end->s6_addr[full] |= (uint8_t) ((1U << (8 - rem)) - 1U);
        full++;
    }

    for (i = full; i < sizeof(end->s6_addr); i++) {
        end->s6_addr[i] = 0xff;
    }
}


static int ipv6_range_cmp(const void *a, const void *b)
{
    const struct fs_ipv6_range *ra, *rb;
    int res;

    ra = a;
    rb = b;

    res = ipv6_addr_cmp(&ra->start, &rb->start);
    if (res) {
        return res;
    }

    return ipv6_addr_cmp(&ra->end, &rb->end);
}


static int build_ipv6_ranges(const struct fs_ipv6_net *nets, size_t nets_cnt,
                             struct fs_ipv6_range **ranges, size_t *ranges_cnt)
{
    struct fs_ipv6_range *new_ranges;
    size_t i, out;

    *ranges = NULL;
    *ranges_cnt = 0;
    if (!nets_cnt) {
        return 0;
    }
    if (nets_cnt > (size_t) -1 / sizeof(*new_ranges)) {
        E("ERROR: %s", strerror(ENOMEM));
        return -1;
    }

    new_ranges = malloc(nets_cnt * sizeof(*new_ranges));
    if (!new_ranges) {
        E("ERROR: malloc(): %s", strerror(errno));
        return -1;
    }

    for (i = 0; i < nets_cnt; i++) {
        memcpy(&new_ranges[i].start, &nets[i].addr,
               sizeof(new_ranges[i].start));
        ipv6_range_end(&nets[i].addr, nets[i].prefix, &new_ranges[i].end);
    }

    qsort(new_ranges, nets_cnt, sizeof(*new_ranges), ipv6_range_cmp);

    out = 0;
    for (i = 1; i < nets_cnt; i++) {
        if (ipv6_addr_cmp(&new_ranges[i].start, &new_ranges[out].end) <= 0) {
            if (ipv6_addr_cmp(&new_ranges[i].end, &new_ranges[out].end) > 0) {
                memcpy(&new_ranges[out].end, &new_ranges[i].end,
                       sizeof(new_ranges[out].end));
            }
        } else {
            out++;
            new_ranges[out] = new_ranges[i];
        }
    }

    *ranges = new_ranges;
    *ranges_cnt = out + 1;

    return 0;
}


static int build_match_ranges(void)
{
    /* Keep parsed CIDRs unchanged for firewall rule generation. */
    /* The normalized interval copies are only used for fast packet matching.
     */
    if (build_ipv4_ranges(g_ctx.filter.allow4, g_ctx.filter.allow4_cnt,
                          &allow4_ranges, &allow4_ranges_cnt) < 0 ||
        build_ipv4_ranges(g_ctx.filter.deny4, g_ctx.filter.deny4_cnt,
                          &deny4_ranges, &deny4_ranges_cnt) < 0 ||
        build_ipv6_ranges(g_ctx.filter.allow6, g_ctx.filter.allow6_cnt,
                          &allow6_ranges, &allow6_ranges_cnt) < 0 ||
        build_ipv6_ranges(g_ctx.filter.deny6, g_ctx.filter.deny6_cnt,
                          &deny6_ranges, &deny6_ranges_cnt) < 0) {
        return -1;
    }

    return 0;
}


int fs_filter_setup(void)
{
    FILE *fp;
    char line[512];
    unsigned long lineno;

    if (!g_ctx.filterpath) {
        return 0;
    }

    fp = fopen(g_ctx.filterpath, "r");
    if (!fp) {
        E("ERROR: fopen(): %s: %s", g_ctx.filterpath, strerror(errno));
        return -1;
    }

    lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        if (!strchr(line, '\n') && !feof(fp)) {
            E("ERROR: %s:%lu: line is too long", g_ctx.filterpath, lineno);
            fclose(fp);
            fs_filter_cleanup();
            return -1;
        }

        if (parse_line(line) < 0) {
            E("ERROR: %s:%lu: failed to parse filter rule", g_ctx.filterpath,
              lineno);
            fclose(fp);
            fs_filter_cleanup();
            return -1;
        }
    }

    if (ferror(fp)) {
        E("ERROR: fgets(): %s: %s", g_ctx.filterpath, strerror(errno));
        fclose(fp);
        fs_filter_cleanup();
        return -1;
    }

    fclose(fp);

    normalize_ports(g_ctx.filter.allow_ports, &g_ctx.filter.allow_ports_cnt);
    normalize_ports(g_ctx.filter.deny_ports, &g_ctx.filter.deny_ports_cnt);
    if (build_match_ranges() < 0) {
        fs_filter_cleanup();
        return -1;
    }
    filter_has_rules = filter_counts_have_rules();
    filter_has_ip_allow = allow4_ranges_cnt || allow6_ranges_cnt;

    E("loaded filter rules: allow ip %zu, deny ip %zu, allow port %zu, deny "
      "port %zu",
      g_ctx.filter.allow4_cnt + g_ctx.filter.allow6_cnt,
      g_ctx.filter.deny4_cnt + g_ctx.filter.deny6_cnt,
      g_ctx.filter.allow_ports_cnt, g_ctx.filter.deny_ports_cnt);

    return 0;
}


void fs_filter_cleanup(void)
{
    free(g_ctx.filter.allow4);
    free(g_ctx.filter.deny4);
    free(g_ctx.filter.allow6);
    free(g_ctx.filter.deny6);
    free(g_ctx.filter.allow_ports);
    free(g_ctx.filter.deny_ports);
    memset(&g_ctx.filter, 0, sizeof(g_ctx.filter));

    free(allow4_ranges);
    free(deny4_ranges);
    free(allow6_ranges);
    free(deny6_ranges);
    allow4_ranges = NULL;
    deny4_ranges = NULL;
    allow6_ranges = NULL;
    deny6_ranges = NULL;
    allow4_ranges_cnt = deny4_ranges_cnt = 0;
    allow6_ranges_cnt = deny6_ranges_cnt = 0;

    allow4_cap = deny4_cap = allow6_cap = deny6_cap = 0;
    allow_ports_cap = deny_ports_cap = 0;
    filter_has_rules = 0;
    filter_has_ip_allow = 0;
}


static int match_ipv4_ranges(const struct sockaddr *addr,
                             const struct fs_ipv4_range *ranges, size_t cnt)
{
    uint32_t ip;
    size_t low, high, mid;

    if (addr->sa_family != AF_INET) {
        return 0;
    }

    ip = ntohl(((const struct sockaddr_in *) addr)->sin_addr.s_addr);
    low = 0;
    high = cnt;
    while (low < high) {
        mid = low + (high - low) / 2;
        if (ip < ranges[mid].start) {
            high = mid;
        } else if (ip > ranges[mid].end) {
            low = mid + 1;
        } else {
            return 1;
        }
    }

    return 0;
}


static int match_ipv6_ranges(const struct sockaddr *addr,
                             const struct fs_ipv6_range *ranges, size_t cnt)
{
    const struct in6_addr *ip;
    size_t low, high, mid;

    if (addr->sa_family != AF_INET6) {
        return 0;
    }

    ip = &((const struct sockaddr_in6 *) addr)->sin6_addr;
    low = 0;
    high = cnt;
    while (low < high) {
        mid = low + (high - low) / 2;
        if (ipv6_addr_cmp(ip, &ranges[mid].start) < 0) {
            high = mid;
        } else if (ipv6_addr_cmp(ip, &ranges[mid].end) > 0) {
            low = mid + 1;
        } else {
            return 1;
        }
    }

    return 0;
}


static int match_ip_ranges(const struct sockaddr *saddr,
                           const struct sockaddr *daddr,
                           const struct fs_ipv4_range *ranges4,
                           size_t ranges4_cnt,
                           const struct fs_ipv6_range *ranges6,
                           size_t ranges6_cnt)
{
    if (saddr->sa_family == AF_INET) {
        return match_ipv4_ranges(saddr, ranges4, ranges4_cnt) ||
               match_ipv4_ranges(daddr, ranges4, ranges4_cnt);
    } else if (saddr->sa_family == AF_INET6) {
        return match_ipv6_ranges(saddr, ranges6, ranges6_cnt) ||
               match_ipv6_ranges(daddr, ranges6, ranges6_cnt);
    }

    return 0;
}


static int match_port_list(uint16_t port, const struct fs_port_range *ports,
                           size_t cnt)
{
    size_t low, high, mid;

    low = 0;
    high = cnt;
    while (low < high) {
        mid = low + (high - low) / 2;
        if (port < ports[mid].start) {
            high = mid;
        } else if (port > ports[mid].end) {
            low = mid + 1;
        } else {
            return 1;
        }
    }

    return 0;
}


int fs_filter_match(const struct sockaddr *saddr, const struct sockaddr *daddr,
                    uint16_t sport_be, uint16_t dport_be)
{
    uint16_t sport, dport;

    if (!filter_has_rules) {
        return 1;
    }

    sport = ntohs(sport_be);
    dport = ntohs(dport_be);

    if (match_ip_ranges(saddr, daddr, deny4_ranges, deny4_ranges_cnt,
                        deny6_ranges, deny6_ranges_cnt) ||
        match_port_list(sport, g_ctx.filter.deny_ports,
                        g_ctx.filter.deny_ports_cnt) ||
        match_port_list(dport, g_ctx.filter.deny_ports,
                        g_ctx.filter.deny_ports_cnt)) {
        return 0;
    }

    if (has_ip_allow() &&
        !match_ip_ranges(saddr, daddr, allow4_ranges, allow4_ranges_cnt,
                         allow6_ranges, allow6_ranges_cnt)) {
        return 0;
    }

    if (g_ctx.filter.allow_ports_cnt &&
        !match_port_list(sport, g_ctx.filter.allow_ports,
                         g_ctx.filter.allow_ports_cnt) &&
        !match_port_list(dport, g_ctx.filter.allow_ports,
                         g_ctx.filter.allow_ports_cnt)) {
        return 0;
    }

    return 1;
}
