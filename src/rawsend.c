/*
 * rawsend.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "rawsend.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

#include "globvar.h"
#include "ipv4pkt.h"
#include "ipv6pkt.h"
#include "logging.h"
#include "payload.h"
#include "srcinfo.h"

#define NO_SNAT   0
#define NEED_SNAT 1

static uint8_t *payload = NULL;
static size_t payload_len = 0;
static int sockfd = -1;
static int sock4fd = -1;
static int sock4if = -1;
static int sock6fd = -1;
static int sock6if = -1;

void fs_rawsend_cleanup(void);

static int hop_estimate(uint8_t ttl)
{
    if (ttl <= 64) {
        return 64 - ttl;
    } else if (ttl <= 128) {
        return 128 - ttl;
    } else {
        return 255 - ttl;
    }
}


static uint8_t calc_snd_ttl(int hops)
{
    int snd_ttl;

    if (!g_ctx.dynamic_pct) {
        return g_ctx.ttl;
    }

    snd_ttl = hops * g_ctx.dynamic_pct / 100;

    if (snd_ttl > g_ctx.ttl) {
        return snd_ttl;
    }

    return g_ctx.ttl;
}


static void ipaddr_to_str(struct sockaddr *addr, char ipstr[INET6_ADDRSTRLEN])
{
    static const char invalid[] = "INVALID";

    const char *res;

    if (addr->sa_family == AF_INET) {
        res = inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr,
                        ipstr, INET_ADDRSTRLEN);
        if (!res) {
            goto invalid;
        }
        return;
    } else if (addr->sa_family == AF_INET6) {
        res = inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addr)->sin6_addr,
                        ipstr, INET6_ADDRSTRLEN);
        if (!res) {
            goto invalid;
        }
        return;
    }

invalid:
    memcpy(ipstr, invalid, sizeof(invalid));
}


static int bind_iface(int fd, int ifindex)
{
    static int use_bindtoifindex = 1;

    int res;
    char *iface, iface_buf[IF_NAMESIZE];

    if (use_bindtoifindex) {
        res = setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &ifindex,
                         sizeof(ifindex));
        if (res < 0 && errno == ENOPROTOOPT) {
            use_bindtoifindex = 0;
        } else if (res < 0) {
            E("ERROR: setsockopt(): SO_BINDTOIFINDEX: %s", strerror(errno));
            return -1;
        } else {
            return 0;
        }
    }

    iface = if_indextoname(ifindex, iface_buf);
    if (!iface) {
        E("ERROR: if_indextoname(): %s", strerror(errno));
        return -1;
    }

    res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_BINDTODEVICE: %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int sendto_snat(struct sockaddr_ll *sll, struct sockaddr *daddr,
                       uint8_t *pkt_buff, int pkt_len)
{
    int res, fd;
    size_t daddrlen;
    ssize_t nbytes;

    if (daddr->sa_family == AF_INET) {
        daddrlen = sizeof(struct sockaddr_in);
        fd = sock4fd;

        if (sll->sll_ifindex != sock4if) {
            res = bind_iface(fd, sll->sll_ifindex);
            if (res < 0) {
                E(T(bind_iface));
                return -1;
            }
            sock4if = sll->sll_ifindex;
        }
    } else if (daddr->sa_family == AF_INET6) {
        daddrlen = sizeof(struct sockaddr_in6);
        fd = sock6fd;

        if (sll->sll_ifindex != sock6if) {
            res = bind_iface(fd, sll->sll_ifindex);
            if (res < 0) {
                E(T(bind_iface));
                return -1;
            }
            sock6if = sll->sll_ifindex;
        }
    } else {
        E("ERROR: Unknown sa_family: %d", (int) daddr->sa_family);
        return -1;
    }

    nbytes = sendto(fd, pkt_buff, pkt_len, 0, daddr, daddrlen);
    if (nbytes < 0 && errno != EPERM) {
        E("ERROR: sendto(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int send_payload(struct sockaddr_ll *sll, struct sockaddr *saddr,
                        struct sockaddr *daddr, uint8_t ttl, uint16_t sport_be,
                        uint16_t dport_be, int need_snat)
{
    int pkt_len;
    ssize_t nbytes;
    uint8_t pkt_buff[1600] __attribute__((aligned));

    if (daddr->sa_family == AF_INET) {
        pkt_len = fs_pkt4_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, payload, payload_len);
        if (pkt_len < 0) {
            E(T(fs_pkt4_make));
            return -1;
        }
    } else if (daddr->sa_family == AF_INET6) {
        pkt_len = fs_pkt6_make(pkt_buff, sizeof(pkt_buff), saddr, daddr, ttl,
                               sport_be, dport_be, payload, payload_len);
        if (pkt_len < 0) {
            E(T(fs_pkt6_make));
            return -1;
        }
    } else {
        E("ERROR: Unknown address family: %d", (int) saddr->sa_family);
        return -1;
    }

    if (need_snat) {
        nbytes = sendto_snat(sll, daddr, pkt_buff, pkt_len);
        if (nbytes < 0) {
            E(T(sendto_snat));
            return -1;
        }
    } else {
        nbytes = sendto(sockfd, pkt_buff, pkt_len, 0, (struct sockaddr *) sll,
                        sizeof(*sll));
        if (nbytes < 0) {
            E("ERROR: sendto(): %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}


int rawsock_setup(int af, int type, int proto)
{
    int res, fd, opt;
    const char *err_hint;

    fd = socket(af, type, proto);
    if (fd < 0) {
        switch (errno) {
            case EPERM:
                err_hint = " (Are you root?)";
                break;
            default:
                err_hint = "";
        }
        E("ERROR: socket(): %s%s", strerror(errno), err_hint);
        return -1;
    }

    res = setsockopt(fd, SOL_SOCKET, SO_MARK, &g_ctx.fwmark,
                     sizeof(g_ctx.fwmark));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_MARK: %s", strerror(errno));
        goto close_socket;
    }

    opt = 7;
    res = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_PRIORITY: %s", strerror(errno));
        goto close_socket;
    }

    /*
        Set SO_RCVBUF to the minimum, since we never call recvfrom() on this
        socket.
    */
    opt = 128;
    res = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
    if (res < 0) {
        E("ERROR: setsockopt(): SO_RCVBUF: %s", strerror(errno));
        goto close_socket;
    }

    return fd;

close_socket:
    close(fd);

    return -1;
}


int fs_rawsend_setup(void)
{
    if (g_ctx.outbound) {
        sockfd = rawsock_setup(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
        if (sockfd < 0) {
            fs_rawsend_cleanup();
            return -1;
        }
    }

    if (g_ctx.inbound && g_ctx.use_ipv4) {
        sock4fd = rawsock_setup(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock4fd < 0) {
            fs_rawsend_cleanup();
            return -1;
        }
    }

    if (g_ctx.inbound && g_ctx.use_ipv6) {
        sock6fd = rawsock_setup(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (sock6fd < 0) {
            fs_rawsend_cleanup();
            return -1;
        }
    }

    return 0;
}


void fs_rawsend_cleanup(void)
{
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }

    if (sock4fd >= 0) {
        close(sock4fd);
        sock4fd = -1;
        sock4if = -1;
    }

    if (sock6fd >= 0) {
        close(sock6fd);
        sock6fd = -1;
        sock6if = -1;
    }
}


int fs_rawsend_handle(struct sockaddr_ll *sll, uint8_t *pkt_data, int pkt_len,
                      int *modified)
{
    uint16_t ethertype;
    int res, i, src_payload_len, hop, srcinfo_unavail;
    uint8_t src_ttl, snd_ttl;
    struct udphdr *udph;
    char src_ip_str[INET6_ADDRSTRLEN], dst_ip_str[INET6_ADDRSTRLEN];
    struct sockaddr_storage saddr_store, daddr_store;
    struct sockaddr *saddr, *daddr;

    *modified = 0;

    saddr = (struct sockaddr *) &saddr_store;
    daddr = (struct sockaddr *) &daddr_store;

    ethertype = ntohs(sll->sll_protocol);
    if (g_ctx.use_ipv4 && ethertype == ETHERTYPE_IP) {
        res = fs_pkt4_parse(pkt_data, pkt_len, saddr, daddr, &src_ttl, &udph,
                            &src_payload_len);
        if (res < 0) {
            E(T(fs_pkt4_parse));
            return -1;
        }
    } else if (g_ctx.use_ipv6 && ethertype == ETHERTYPE_IPV6) {
        res = fs_pkt6_parse(pkt_data, pkt_len, saddr, daddr, &src_ttl, &udph,
                            &src_payload_len);
        if (res < 0) {
            E(T(fs_pkt6_parse));
            return -1;
        }
    } else {
        E("ERROR: unknown ethertype 0x%04x", ethertype);
        return -1;
    }

    if (!g_ctx.silent) {
        ipaddr_to_str(saddr, src_ip_str);
        ipaddr_to_str(daddr, dst_ip_str);
    }

    if (sll->sll_pkttype == PACKET_HOST) {
        /*
            Inbound UDP packet.
        */
        sll->sll_pkttype = 0;

        if (!g_ctx.outbound) {
            E_INFO("%s:%u ===UDP(~)===> %s:%u", src_ip_str,
                   ntohs(udph->source), dst_ip_str, ntohs(udph->dest));
            return NF_ACCEPT;
        }

        E_INFO("%s:%u ===UDP===> %s:%u", src_ip_str, ntohs(udph->source),
               dst_ip_str, ntohs(udph->dest));

        snd_ttl = g_ctx.ttl;

        if (!g_ctx.nohopest) {
            hop = hop_estimate(src_ttl);
            if (hop <= g_ctx.ttl) {
                E_INFO("%s:%u ===LOCAL(~)===> %s:%u", src_ip_str,
                       ntohs(udph->source), dst_ip_str, ntohs(udph->dest));
                return NF_ACCEPT;
            }
            snd_ttl = calc_snd_ttl(hop);
        }

        th_payload_get(&payload, &payload_len);

        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_payload(sll, daddr, saddr, snd_ttl, udph->dest,
                               udph->source, NO_SNAT);
            if (res < 0) {
                E(T(send_payload));
                return -1;
            }
        }
        E_INFO("%s:%u <===FAKE(*)=== %s:%u", src_ip_str, ntohs(udph->source),
               dst_ip_str, ntohs(udph->dest));

        return NF_ACCEPT;
    } else if (sll->sll_pkttype == PACKET_OUTGOING) {
        /*
            Outbound UDP packet.
        */
        sll->sll_pkttype = 0;

        srcinfo_unavail = fs_srcinfo_get(daddr, &src_ttl, sll->sll_addr);
        if (srcinfo_unavail) {
            src_ttl = 0;
            memset(&sll->sll_addr, 0, sizeof(sll->sll_addr));
        }

        if (!g_ctx.inbound) {
            E_INFO("%s:%u <===UDP(~)=== %s:%u", dst_ip_str, ntohs(udph->dest),
                   src_ip_str, ntohs(udph->source));
            return NF_ACCEPT;
        }

        snd_ttl = g_ctx.ttl;

        if (!g_ctx.nohopest) {
            hop = hop_estimate(src_ttl);
            if (hop <= g_ctx.ttl) {
                E_INFO("%s:%u <===LOCAL(~)=== %s:%u", src_ip_str,
                       ntohs(udph->source), dst_ip_str, ntohs(udph->dest));
                return NF_ACCEPT;
            }
            snd_ttl = calc_snd_ttl(hop);
        }

        th_payload_get(&payload, &payload_len);

        for (i = 0; i < g_ctx.repeat; i++) {
            res = send_payload(sll, saddr, daddr, snd_ttl, udph->source,
                               udph->dest, NEED_SNAT);
            if (res < 0) {
                E(T(send_payload));
                return -1;
            }
        }
        E_INFO("%s:%u <===FAKE(*)=== %s:%u", dst_ip_str, ntohs(udph->dest),
               src_ip_str, ntohs(udph->source));


        E_INFO("%s:%u <===UDP=== %s:%u", dst_ip_str, ntohs(udph->dest),
               src_ip_str, ntohs(udph->source));

        return NF_ACCEPT;
    } else {
        E_INFO("%s:%u ===(~)=== %s:%u", src_ip_str, ntohs(udph->source),
               dst_ip_str, ntohs(udph->dest));
        return NF_ACCEPT;
    }
}
