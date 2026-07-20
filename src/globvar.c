/*
 * globvar.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "globvar.h"

#include <stdint.h>
#include <stdio.h>

struct fs_context g_ctx = {.exit = 0,
                           .logfp = NULL,

                           /* -b, -u */ .plinfo = NULL,
                           /* -0 */ .inbound = 0,
                           /* -1 */ .outbound = 0,
                           /* -4 */ .use_ipv4 = 0,
                           /* -6 */ .use_ipv6 = 0,
                           /* -a */ .alliface = 0,
                           /* -d */ .daemon = 0,
                           /* -f */ .skipfw = 0,
                           /* -g */ .nohopest = 0,
                           /* -i */ .iface = NULL,
                           /* -k */ .killproc = 0,
                           /* -l */ .filterpath = NULL,
                           /* -m */ .fwmark = 0x10000,
                           /* -n */ .nfqnum = 513,
                           /* -r */ .repeat = 2,
                           /* -s */ .silent = 0,
                           /* -t */ .ttl = 3,
                           /* -w */ .logpath = NULL,
                           /* -x */ .fwmask = 0,
                           /* -y */ .dynamic_pct = 0,
                           /* -z */ .use_iptables = 0,

                           .filter = {0}};
