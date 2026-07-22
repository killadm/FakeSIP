/*
 * nfqueue.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "nfqueue.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "globvar.h"
#include "logging.h"
#include "rawsend.h"
#include "signals.h"

static int fd = -1;
static struct nfq_handle *h = NULL;
static struct nfq_q_handle *qh = NULL;

/* FakeSIP only inspects IP/UDP headers and never modifies queued packets. */
#define FS_NFQ_COPY_RANGE      128
#define FS_NFQ_POLL_TIMEOUT_MS 5000
#define FS_NFQ_QUEUE_MAXLEN    4096
#define FS_NFQ_RCVBUF_SIZE     (4 * 1024 * 1024)

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{
    uint32_t pkt_id, iifindex, oifindex;
    uint16_t hw_addrlen;
    int verdict, pkt_len, modified;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkt_data;
    struct nfqnl_msg_packet_hw *hwph;
    struct sockaddr_ll sll;

    (void) nfmsg;
    (void) data;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        EE("ERROR: nfq_get_msg_packet_hdr(): %s", "failure");
        return -1;
    }

    pkt_id = ntohl(ph->packet_id);

    iifindex = nfq_get_indev(nfa);
    oifindex = nfq_get_outdev(nfa);

    pkt_data = NULL;
    pkt_len = nfq_get_payload(nfa, &pkt_data);
    if (pkt_len < 0 || !pkt_data) {
        EE("ERROR: nfq_get_payload(): %s", "failure");
        goto ret_accept;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = ph->hw_protocol;
    if (oifindex) {
        sll.sll_pkttype = PACKET_OUTGOING;
        sll.sll_ifindex = oifindex;
    } else if (iifindex) {
        sll.sll_pkttype = PACKET_HOST;
        sll.sll_ifindex = iifindex;
    } else {
        EE("ERROR: Failed to get interface index");
        goto ret_accept;
    }

    /* hwph can be null on PPP interfaces or POSTROUTING packets */
    hwph = nfq_get_packet_hw(nfa);
    if (hwph) {
        hw_addrlen = ntohs(hwph->hw_addrlen);
        if (hw_addrlen > sizeof(sll.sll_addr)) {
            hw_addrlen = sizeof(sll.sll_addr);
        }
        sll.sll_halen = hw_addrlen;
        memcpy(sll.sll_addr, hwph->hw_addr, hw_addrlen);
    } else {
        sll.sll_halen = 0;
        memset(sll.sll_addr, 0, sizeof(sll.sll_addr));
    }

    verdict = fs_rawsend_handle(&sll, pkt_data, pkt_len, &modified);
    if (verdict < 0) {
        EE(T(fs_rawsend_handle));
        goto ret_accept;
    }

    if (modified && verdict != NF_DROP) {
        return nfq_set_verdict(qh, pkt_id, verdict, pkt_len, pkt_data);
    }

    return nfq_set_verdict(qh, pkt_id, verdict, 0, NULL);

ret_accept:
    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
}


int fs_nfq_setup(void)
{
    int res, opt;
    char *err_hint;
    socklen_t opt_len;

    h = nfq_open();
    if (!h) {
        switch (errno) {
            case EPERM:
                err_hint = " (Are you root?)";
                break;
            case EINVAL:
                err_hint = " (Missing kernel module?)";
                break;
            default:
                err_hint = "";
        }
        E("ERROR: nfq_open(): %s%s", strerror(errno), err_hint);
        return -1;
    }

    qh = nfq_create_queue(h, g_ctx.nfqnum, &callback, NULL);
    if (!qh) {
        switch (errno) {
            case EPERM:
                res = fs_kill_running(0);
                errno = EPERM;
                if (res < 0) {
                    err_hint = " (Another process is running / Are you root?)";
                } else {
                    err_hint = " (Another process is running)";
                }
                break;
            case EINVAL:
                err_hint = " (Missing kernel module?)";
                break;
            default:
                err_hint = "";
        }
        E("ERROR: nfq_create_queue(): %s%s", strerror(errno), err_hint);
        goto close_nfq;
    }

    res = nfq_set_mode(qh, NFQNL_COPY_PACKET, FS_NFQ_COPY_RANGE);
    if (res < 0) {
        E("ERROR: nfq_set_mode(): NFQNL_COPY_PACKET: %s", strerror(errno));
        goto destroy_queue;
    }

    res = nfq_set_queue_maxlen(qh, FS_NFQ_QUEUE_MAXLEN);
    if (res < 0) {
        E("WARNING: nfq_set_queue_maxlen(): %s", strerror(errno));
    }

    res = nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);
    if (res < 0) {
        E("ERROR: nfq_set_queue_flags(): NFQA_CFG_F_FAIL_OPEN: %s",
          strerror(errno));
        goto destroy_queue;
    }

#ifdef NFQA_CFG_F_GSO
    res = nfq_set_queue_flags(qh, NFQA_CFG_F_GSO, NFQA_CFG_F_GSO);
    if (res < 0) {
        E("WARNING: nfq_set_queue_flags(): NFQA_CFG_F_GSO: %s",
          strerror(errno));
    }
#endif

    fd = nfq_fd(h);
    res = fcntl(fd, F_GETFL, 0);
    if (res < 0) {
        E("ERROR: fcntl(): F_GETFL: %s", strerror(errno));
        goto destroy_queue;
    }

    if (fcntl(fd, F_SETFL, res | O_NONBLOCK) < 0) {
        E("ERROR: fcntl(): F_SETFL: %s", strerror(errno));
        goto destroy_queue;
    }

    opt_len = sizeof(opt);
    res = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, &opt_len);
    if (res < 0) {
        E("ERROR: getsockopt(): SO_RCVBUF: %s", strerror(errno));
        goto destroy_queue;
    }

    if (opt < FS_NFQ_RCVBUF_SIZE) {
        opt = FS_NFQ_RCVBUF_SIZE;
        res = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &opt, sizeof(opt));
        if (res < 0) {
            E("WARNING: setsockopt(): SO_RCVBUFFORCE: %s", strerror(errno));
            res = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
            if (res < 0) {
                E("WARNING: setsockopt(): SO_RCVBUF: %s", strerror(errno));
            }
        }
    }

#if defined(SOL_NETLINK) && defined(NETLINK_NO_ENOBUFS)
    opt = 1;
    res = setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(opt));
    if (res < 0) {
        E("WARNING: setsockopt(): NETLINK_NO_ENOBUFS: %s", strerror(errno));
    }
#endif

    return 0;

destroy_queue:
    nfq_destroy_queue(qh);

close_nfq:
    nfq_close(h);

    return -1;
}


void fs_nfq_cleanup(void)
{
    if (qh) {
        nfq_destroy_queue(qh);
        qh = NULL;
    }

    if (h) {
        nfq_close(h);
        h = NULL;
        fd = -1;
    }
}


int fs_nfq_loop(void)
{
    static const size_t buffsize = UINT16_MAX;

    struct pollfd pfd;
    int res, ret, err_cnt, transient_err_logged;
    ssize_t recv_len;
    char *buff;

    buff = malloc(buffsize);
    if (!buff) {
        E("ERROR: malloc(): %s", strerror(errno));
        return -1;
    }

    err_cnt = 0;
    transient_err_logged = 0;

    while (!fs_signal_exit_requested()) {
        if (err_cnt >= 20) {
            E("too many errors, exiting...");
            ret = -1;
            goto free_buff;
        }

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        res = poll(&pfd, 1, FS_NFQ_POLL_TIMEOUT_MS);
        if (res < 0) {
            if (errno == EINTR) {
                continue;
            }
            err_cnt++;
            E("ERROR: poll(): %s", strerror(errno));
            continue;
        }
        if (!res) {
            continue;
        }
        if (!(pfd.revents & POLLIN)) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                err_cnt++;
                E("ERROR: nfqueue socket poll(): revents=0x%x", pfd.revents);
            }
            continue;
        }

        while (!fs_signal_exit_requested()) {
            recv_len = recv(fd, buff, buffsize, MSG_DONTWAIT);
            if (recv_len < 0) {
                switch (errno) {
                    case EINTR:
                        continue;
                    case EAGAIN:
                        break;
                    case ETIMEDOUT:
                    case ENOBUFS:
                        if (!transient_err_logged) {
                            E("WARNING: recv(): %s; suppressing repeated "
                              "transient errors",
                              strerror(errno));
                            transient_err_logged = 1;
                        }
                        break;
                    default:
                        err_cnt++;
                        E("ERROR: recv(): %s", strerror(errno));
                        ret = -1;
                        goto free_buff;
                }

                break;
            }

            res = nfq_handle_packet(h, buff, recv_len);
            if (res < 0) {
                err_cnt++;
                E("ERROR: nfq_handle_packet(): %s", "failure");
                break;
            }

            err_cnt = 0;
            transient_err_logged = 0;
        }
    }

    ret = 0;

free_buff:
    free(buff);

    return ret;
}
