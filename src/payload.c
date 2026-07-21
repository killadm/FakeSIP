/*
 * payload.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "payload.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "logging.h"
#include "globvar.h"

#define BUFFLEN 1200
#define SET_BE16(a, u16)         \
    do {                         \
        (a)[0] = (u16) >> (8);   \
        (a)[1] = (u16) & (0xff); \
    } while (0)

struct payload_node {
    uint8_t payload[BUFFLEN];
    size_t payload_len;
    struct payload_node *next;
};

/*
    Media port 0 marks the stream inactive. Linux SIP conntrack skips RTP

 * expectations for it, avoiding expectation table pressure on routers.
*/
static const char *sdp_fmt = "v=0\r\n"
                             "o=Admin %lu %lu IN IP4 %s\r\n"
                             "s=-\r\n"
                             "c=IN IP4 %s\r\n"
                             "t=0 0\r\n"
                             "m=audio 0 RTP/AVP 0\r\n"
                             "a=inactive\r\n"
                             "a=rtpmap:0 PCMU/8000\r\n";

static const char *sip_fmt = "INVITE %s SIP/2.0\r\n"
                             "Via: SIP/2.0/UDP %s;branch=%lx\r\n"
                             "From: <sip:%s>;tag=%lx\r\n"
                             "To: \"%s\" <%s>\r\n"
                             "Call-ID: %lx@%s\r\n"
                             "CSeq: 1 INVITE\r\n"
                             "Contact: <sip:%s>\r\n"
                             "Content-Type: application/sdp\r\n"
                             "Content-Length: %lu\r\n"
                             "\r\n"
                             "%s";

static struct payload_node *current_node;

static int make_sip_invite(uint8_t *buffer, size_t *len, char *sip_uri)
{
    int i, len_, buffsize;
    char sip_uri_random[64], local[64], sdp_buf[180], *username;
    unsigned long rand_ul[5], content_length;

    for (i = 0; i < 5; i++) {
        rand_ul[i] = rand() * (ULONG_MAX / RAND_MAX);
    }

    if (sip_uri) {
        if (strncmp("sip:", sip_uri, 4) != 0) {
            E("ERROR: Invalid SIP URI (should start with `sip:`): %s",
              sip_uri);
            return -1;
        }
    } else {
        len_ = snprintf(sip_uri_random, sizeof(sip_uri_random),
                        "sip:user@203.0.113.%d", rand() % UINT8_MAX);
        if (len_ < 0 || (size_t) len_ >= sizeof(sip_uri_random)) {
            E("ERROR: snprintf(): %s", "failure");
            return -1;
        }
        sip_uri = sip_uri_random;
    }
    username = sip_uri + 4;

    len_ = snprintf(local, sizeof(local), "198.51.100.%d", rand() % UINT8_MAX);
    if (len_ < 0 || (size_t) len_ >= sizeof(local)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    len_ = snprintf(sdp_buf, sizeof(sdp_buf), sdp_fmt, rand_ul[0] & UINT32_MAX,
                    rand_ul[1] & UINT32_MAX, local, local);
    if (len_ < 0 || (size_t) len_ >= sizeof(sdp_buf)) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    }

    content_length = len_;

    buffsize = *len;
    len_ = snprintf((char *) buffer, buffsize, sip_fmt, sip_uri, local,
                    rand_ul[2], local, rand_ul[3], username, sip_uri,
                    rand_ul[4], local, local, content_length, sdp_buf);
    if (len_ < 0) {
        E("ERROR: snprintf(): %s", "failure");
        return -1;
    } else if (len_ >= buffsize) {
        E("ERROR: SIP URI is too long");
        return -1;
    }

    *len = len_;

    return 0;
}


static int make_custom(uint8_t *buffer, size_t *len, char *filepath)
{
    int res, len_, buffsize;
    FILE *fp;

    len_ = 0;
    buffsize = *len;

    fp = fopen(filepath, "rb");
    if (!fp) {
        E("ERROR: fopen(): %s: %s", filepath, strerror(errno));
        return -1;
    }

    while (!feof(fp) && !ferror(fp) && len_ < buffsize) {
        len_ += fread(buffer + len_, 1, buffsize - len_, fp);
    }

    if (ferror(fp)) {
        E("ERROR: fread(): %s: %s", filepath, "failure");
        fclose(fp);
        return -1;
    }

    if (!feof(fp)) {
        E("ERROR: %s: Data too long. Maximum length is %d", filepath,
          buffsize);
        fclose(fp);
        return -1;
    }

    res = fclose(fp);
    if (res < 0) {
        E("ERROR: fclose(): %s", strerror(errno));
        return -1;
    }

    *len = len_;

    return 0;
}


int fs_payload_setup(void)
{
    int res;
    size_t len;
    struct payload_info *pinfo;
    struct payload_node *node, *next;

    for (pinfo = g_ctx.plinfo; pinfo->type; pinfo++) {
        node = malloc(sizeof(*node));
        if (!node) {
            E("ERROR: malloc(): %s", strerror(errno));
            goto cleanup;
        }

        if (current_node) {
            next = current_node->next;
            current_node->next = node;
            node->next = next;
        } else {
            current_node = node;
            node->next = node;
        }

        switch (pinfo->type) {
            case FS_PAYLOAD_CUSTOM:
                len = sizeof(node->payload);
                res = make_custom(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_custom));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            case FS_PAYLOAD_SIP:
                len = sizeof(node->payload);
                res = make_sip_invite(node->payload, &len, pinfo->info);
                if (res < 0) {
                    E(T(make_sip_invite));
                    goto cleanup;
                }
                node->payload_len = len;
                break;

            default:
                E("ERROR: Unknown payload type");
                goto cleanup;
        }
    }

    if (!current_node) {
        E("ERROR: No payload is available");
        goto cleanup;
    }

    current_node = current_node->next;

    return 0;

cleanup:
    fs_payload_cleanup();

    return -1;
}


void fs_payload_cleanup(void)
{
    struct payload_node *node, *next_node;

    node = current_node;
    while (node) {
        next_node = node->next;
        free(node);
        if (next_node == current_node) {
            break;
        }
        node = next_node;
    }
}


void th_payload_get(uint8_t **payload_ptr, size_t *payload_len)
{
    *payload_ptr = current_node->payload;
    *payload_len = current_node->payload_len;
    current_node = current_node->next;
}
