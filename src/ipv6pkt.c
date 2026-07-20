/*
 * ipv6pkt.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "ipv6pkt.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

#include "globvar.h"
#include "logging.h"

int fs_pkt6_parse(void *pkt_data, int pkt_len, struct sockaddr *saddr,
                  struct sockaddr *daddr, uint8_t *ttl,
                  struct udphdr **udph_ptr, int *udp_payload_len)
{
    struct ip6_hdr *ip6h;
    struct udphdr *udph;
    int ip6h_len;
    struct sockaddr_in6 *saddr_in6, *daddr_in6;

    saddr_in6 = (struct sockaddr_in6 *) saddr;
    daddr_in6 = (struct sockaddr_in6 *) daddr;

    ip6h_len = sizeof(*ip6h);

    if (pkt_len < ip6h_len) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    ip6h = (struct ip6_hdr *) pkt_data;

    if (ip6h->ip6_nxt != IPPROTO_UDP) {
        E("ERROR: not a UDP packet (next header %d)", (int) ip6h->ip6_nxt);
        return -1;
    }

    if ((size_t) pkt_len < ip6h_len + sizeof(*udph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    udph = (struct udphdr *) ((uint8_t *) pkt_data + ip6h_len);

    memset(saddr_in6, 0, sizeof(*saddr_in6));
    saddr_in6->sin6_family = AF_INET6;
    memcpy(&saddr_in6->sin6_addr, &ip6h->ip6_src, sizeof(struct in6_addr));

    memset(daddr_in6, 0, sizeof(*daddr_in6));
    daddr_in6->sin6_family = AF_INET6;
    memcpy(&daddr_in6->sin6_addr, &ip6h->ip6_dst, sizeof(struct in6_addr));

    *ttl = ip6h->ip6_hlim;
    *udph_ptr = udph;
    *udp_payload_len = pkt_len - ip6h_len - sizeof(*udph);

    return 0;
}


int fs_pkt6_make(uint8_t *buffer, size_t buffer_size, struct sockaddr *saddr,
                 struct sockaddr *daddr, uint8_t ttl, uint16_t sport_be,
                 uint16_t dport_be, uint8_t *udp_payload,
                 size_t udp_payload_size)
{
    size_t pkt_len;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;
    uint8_t *udppl;
    struct sockaddr_in6 *saddr_in6, *daddr_in6;

    if (saddr->sa_family != AF_INET6 || daddr->sa_family != AF_INET6) {
        E("ERROR: Invalid address family");
        return -1;
    }

    saddr_in6 = (struct sockaddr_in6 *) saddr;
    daddr_in6 = (struct sockaddr_in6 *) daddr;

    pkt_len = sizeof(*ip6h) + sizeof(*udph) + udp_payload_size;
    if (buffer_size < pkt_len + 1) {
        E("ERROR: %s", strerror(ENOBUFS));
        return -1;
    }

    ip6h = (struct ip6_hdr *) buffer;
    udph = (struct udphdr *) (buffer + sizeof(*ip6h));
    udppl = buffer + sizeof(*ip6h) + sizeof(*udph);

    memset(ip6h, 0, sizeof(*ip6h));
    ip6h->ip6_flow = htonl((6 << 28) /* version */ | (0 << 20) /* traffic */ |
                           0 /* flow */);
    ip6h->ip6_plen = htons(sizeof(*udph) + udp_payload_size);
    ip6h->ip6_nxt = IPPROTO_UDP;
    ip6h->ip6_hops = ttl;
    memcpy(&ip6h->ip6_src, &saddr_in6->sin6_addr, sizeof(struct in6_addr));
    memcpy(&ip6h->ip6_dst, &daddr_in6->sin6_addr, sizeof(struct in6_addr));

    memset(udph, 0, sizeof(*udph));
    udph->source = sport_be;
    udph->dest = dport_be;
    udph->len = htons(sizeof(*udph) + udp_payload_size);
    udph->check = 0;

    if (udp_payload_size) {
        memcpy(udppl, udp_payload, udp_payload_size);
    }

    nfq_udp_compute_checksum_ipv6(udph, ip6h);

    return pkt_len;
}
