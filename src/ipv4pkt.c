/*
 * ipv4pkt.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "ipv4pkt.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

#include "globvar.h"
#include "logging.h"

int fs_pkt4_parse(void *pkt_data, int pkt_len, struct sockaddr *saddr,
                  struct sockaddr *daddr, uint8_t *ttl,
                  struct udphdr **udph_ptr, int *udp_payload_len)
{
    struct iphdr *iph;
    struct udphdr *udph;
    int iph_len;
    struct sockaddr_in *saddr_in, *daddr_in;

    saddr_in = (struct sockaddr_in *) saddr;
    daddr_in = (struct sockaddr_in *) daddr;

    if ((size_t) pkt_len < sizeof(*iph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    iph = (struct iphdr *) pkt_data;
    iph_len = iph->ihl * 4;

    if ((size_t) iph_len < sizeof(*iph)) {
        E("ERROR: invalid IP header length: %d", iph_len);
        return -1;
    }

    if (iph->protocol != IPPROTO_UDP) {
        E("ERROR: not a UDP packet (protocol %d)", (int) iph->protocol);
        return -1;
    }

    if (pkt_len < iph_len + (int) sizeof(*udph)) {
        E("ERROR: invalid packet length: %d", pkt_len);
        return -1;
    }

    udph = (struct udphdr *) ((uint8_t *) pkt_data + iph_len);

    memset(saddr_in, 0, sizeof(*saddr_in));
    saddr_in->sin_family = AF_INET;
    saddr_in->sin_addr.s_addr = iph->saddr;

    memset(daddr_in, 0, sizeof(*daddr_in));
    daddr_in->sin_family = AF_INET;
    daddr_in->sin_addr.s_addr = iph->daddr;

    *ttl = iph->ttl;
    *udph_ptr = udph;
    *udp_payload_len = pkt_len - iph_len - sizeof(*udph);

    return 0;
}


int fs_pkt4_make(uint8_t *buffer, size_t buffer_size, struct sockaddr *saddr,
                 struct sockaddr *daddr, uint8_t ttl, uint16_t sport_be,
                 uint16_t dport_be, uint8_t *udp_payload,
                 size_t udp_payload_size)
{
    size_t pkt_len;
    struct iphdr *iph;
    struct udphdr *udph;
    uint8_t *udppl;
    struct sockaddr_in *saddr_in, *daddr_in;

    if (saddr->sa_family != AF_INET || daddr->sa_family != AF_INET) {
        E("ERROR: Invalid address family");
        return -1;
    }

    saddr_in = (struct sockaddr_in *) saddr;
    daddr_in = (struct sockaddr_in *) daddr;

    pkt_len = sizeof(*iph) + sizeof(*udph) + udp_payload_size;
    if (buffer_size < pkt_len + 1) {
        E("ERROR: %s", strerror(ENOBUFS));
        return -1;
    }

    iph = (struct iphdr *) buffer;
    udph = (struct udphdr *) (buffer + sizeof(*iph));
    udppl = buffer + sizeof(*iph) + sizeof(*udph);

    memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = sizeof(*iph) / 4;
    iph->tos = 0;
    iph->tot_len = htons(pkt_len);
    iph->id = ((rand() & 0xff) << 8) | (rand() & 0xff);
    iph->frag_off = htons(1 << 14 /* DF */);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = saddr_in->sin_addr.s_addr;
    iph->daddr = daddr_in->sin_addr.s_addr;

    memset(udph, 0, sizeof(*udph));
    udph->source = sport_be;
    udph->dest = dport_be;
    udph->len = htons(sizeof(*udph) + udp_payload_size);
    udph->check = 0;

    if (udp_payload_size) {
        memcpy(udppl, udp_payload, udp_payload_size);
    }

    nfq_ip_set_checksum(iph);
    nfq_udp_compute_checksum_ipv4(udph, iph);

    return pkt_len;
}
