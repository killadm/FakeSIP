/*
 * filter.h - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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

#ifndef FS_FILTER_H
#define FS_FILTER_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

struct fs_ipv4_net {
    uint32_t addr;
    uint32_t mask;
    uint8_t prefix;
};

struct fs_ipv6_net {
    struct in6_addr addr;
    uint8_t prefix;
};

struct fs_port_range {
    uint16_t start;
    uint16_t end;
};

struct fs_filter {
    struct fs_ipv4_net *allow4;
    size_t allow4_cnt;
    struct fs_ipv4_net *deny4;
    size_t deny4_cnt;

    struct fs_ipv6_net *allow6;
    size_t allow6_cnt;
    struct fs_ipv6_net *deny6;
    size_t deny6_cnt;

    struct fs_port_range *allow_ports;
    size_t allow_ports_cnt;
    struct fs_port_range *deny_ports;
    size_t deny_ports_cnt;
};

int fs_filter_setup(void);

void fs_filter_cleanup(void);

int fs_filter_match(const struct sockaddr *saddr, const struct sockaddr *daddr,
                    uint16_t sport_be, uint16_t dport_be);

int fs_filter_has_rules(void);

#endif /* FS_FILTER_H */
