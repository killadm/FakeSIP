/*
 * srcinfo.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "srcinfo.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "logging.h"

#define CAPACITY   500
#define HASH_SIZE  1024
#define HASH_EMPTY SIZE_MAX

struct srcinfo {
    int initialized;
    uint32_t hash;
    uint8_t ttl;
    uint8_t hwaddr[8];
    struct sockaddr_storage addr;
};

static struct srcinfo *srci = NULL;
static size_t *srci_hash = NULL;
static size_t srci_end = 0;

static uint32_t mix32(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static uint32_t sockaddr_hash(const struct sockaddr *addr)
{
    const struct sockaddr_in *addr_in;
    const struct sockaddr_in6 *addr_in6;
    const uint8_t *bytes;
    uint32_t hash = 2166136261U;
    size_t i;

    if (addr->sa_family == AF_INET) {
        addr_in = (const struct sockaddr_in *) addr;
        return mix32(ntohl(addr_in->sin_addr.s_addr) ^ AF_INET);
    }

    addr_in6 = (const struct sockaddr_in6 *) addr;
    bytes = (const uint8_t *) &addr_in6->sin6_addr;
    for (i = 0; i < sizeof(addr_in6->sin6_addr); i++) {
        hash ^= bytes[i];
        hash *= 16777619U;
    }
    return mix32(hash ^ AF_INET6);
}

static int sameip(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    const struct sockaddr_in *addr_in_1, *addr_in_2;
    const struct sockaddr_in6 *addr_in6_1, *addr_in6_2;

    if (addr1->sa_family != addr2->sa_family) {
        return 0;
    }

    if (addr1->sa_family == AF_INET) {
        addr_in_1 = (struct sockaddr_in *) addr1;
        addr_in_2 = (struct sockaddr_in *) addr2;

        return addr_in_1->sin_addr.s_addr == addr_in_2->sin_addr.s_addr;
    } else if (addr1->sa_family == AF_INET6) {
        addr_in6_1 = (struct sockaddr_in6 *) addr1;
        addr_in6_2 = (struct sockaddr_in6 *) addr2;

        return memcmp(&addr_in6_1->sin6_addr, &addr_in6_2->sin6_addr,
                      sizeof(addr_in6_1->sin6_addr)) == 0;
    }
    return 0;
}

static int copy_addr(struct sockaddr_storage *dst, const struct sockaddr *src)
{
    if (src->sa_family == AF_INET) {
        memcpy(dst, src, sizeof(struct sockaddr_in));
        return 0;
    } else if (src->sa_family == AF_INET6) {
        memcpy(dst, src, sizeof(struct sockaddr_in6));
        return 0;
    }

    E("ERROR: Unknown sa_family: %d", (int) src->sa_family);
    return -1;
}

static int insert_hash_entry(size_t idx)
{
    size_t slot = srci[idx].hash & (HASH_SIZE - 1);
    size_t i;

    for (i = 0; i < HASH_SIZE; i++) {
        if (srci_hash[slot] == HASH_EMPTY) {
            srci_hash[slot] = idx;
            return 0;
        }
        slot = (slot + 1) & (HASH_SIZE - 1);
    }

    E("ERROR: srcinfo hash table full");
    return -1;
}

static void rehash_after_remove(size_t empty_slot)
{
    size_t slot = (empty_slot + 1) & (HASH_SIZE - 1);
    size_t idx;

    while (srci_hash[slot] != HASH_EMPTY) {
        idx = srci_hash[slot];
        srci_hash[slot] = HASH_EMPTY;
        (void) insert_hash_entry(idx);
        slot = (slot + 1) & (HASH_SIZE - 1);
    }
}

static void remove_hash_entry(size_t idx)
{
    size_t slot;
    size_t i;

    if (!srci[idx].initialized) {
        return;
    }

    slot = srci[idx].hash & (HASH_SIZE - 1);
    for (i = 0; i < HASH_SIZE; i++) {
        if (srci_hash[slot] == HASH_EMPTY) {
            return;
        }

        if (srci_hash[slot] == idx) {
            srci_hash[slot] = HASH_EMPTY;
            rehash_after_remove(slot);
            return;
        }

        slot = (slot + 1) & (HASH_SIZE - 1);
    }
}

static size_t find_hash_slot(const struct sockaddr *addr, uint32_t hash,
                             int *found)
{
    size_t slot = hash & (HASH_SIZE - 1);
    size_t idx;
    size_t i;

    for (i = 0; i < HASH_SIZE; i++) {
        idx = srci_hash[slot];
        if (idx == HASH_EMPTY) {
            *found = 0;
            return slot;
        }

        if (srci[idx].initialized && srci[idx].hash == hash &&
            sameip(addr, (const struct sockaddr *) &srci[idx].addr)) {
            *found = 1;
            return slot;
        }

        slot = (slot + 1) & (HASH_SIZE - 1);
    }

    *found = 0;
    return HASH_EMPTY;
}

int fs_srcinfo_setup(void)
{
    size_t i;

    srci = calloc(CAPACITY, sizeof(*srci));
    if (!srci) {
        E("ERROR: calloc(): %s", strerror(errno));
        return -1;
    }

    srci_hash = malloc(HASH_SIZE * sizeof(*srci_hash));
    if (!srci_hash) {
        E("ERROR: malloc(): %s", strerror(errno));
        free(srci);
        srci = NULL;
        return -1;
    }

    for (i = 0; i < HASH_SIZE; i++) {
        srci_hash[i] = HASH_EMPTY;
    }

    srci_end = 0;

    return 0;
}


void fs_srcinfo_cleanup(void)
{
    free(srci);
    free(srci_hash);
    srci = NULL;
    srci_hash = NULL;
    srci_end = 0;
}


int fs_srcinfo_put(struct sockaddr *addr, uint8_t ttl, uint8_t hwaddr[8])
{
    struct srcinfo *info;
    uint32_t hash;
    size_t slot;
    size_t idx;
    int found;

    if (!srci || !srci_hash) {
        return -1;
    }

    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        E("ERROR: Unknown sa_family: %d", (int) addr->sa_family);
        return -1;
    }

    hash = sockaddr_hash(addr);
    slot = find_hash_slot(addr, hash, &found);
    if (slot == HASH_EMPTY) {
        return -1;
    }

    if (found) {
        idx = srci_hash[slot];
    } else {
        idx = srci_end;
        remove_hash_entry(idx);
    }

    info = &srci[idx];
    if (copy_addr(&info->addr, addr) < 0) {
        return -1;
    }

    info->hash = hash;
    info->ttl = ttl;
    memcpy(info->hwaddr, hwaddr, sizeof(info->hwaddr));
    info->initialized = 1;

    if (!found) {
        if (insert_hash_entry(idx) < 0) {
            info->initialized = 0;
            return -1;
        }
        srci_end = (srci_end + 1) % CAPACITY;
    }

    return 0;
}


int fs_srcinfo_get(struct sockaddr *addr, uint8_t *ttl, uint8_t hwaddr[8])
{
    struct srcinfo *info;
    uint32_t hash;
    size_t slot;
    int found;

    if (!srci || !srci_hash) {
        return 1;
    }

    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return 1;
    }

    hash = sockaddr_hash(addr);
    slot = find_hash_slot(addr, hash, &found);
    if (slot == HASH_EMPTY || !found) {
        return 1;
    }

    info = &srci[srci_hash[slot]];
    *ttl = info->ttl;
    memcpy(hwaddr, info->hwaddr, sizeof(info->hwaddr));
    return 0;
}
