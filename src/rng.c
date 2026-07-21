/*
 * rng.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "rng.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static uint64_t rng_state = 0;

static uint64_t fallback_seed(void)
{
    uint64_t seed;

    seed = (uint64_t) time(NULL);
    seed ^= (uint64_t) getpid() << 32;
    seed ^= (uint64_t) (uintptr_t) &seed;

    if (!seed) {
        seed = 0x9e3779b97f4a7c15ULL;
    }

    return seed;
}


static void seed_rng(void)
{
    uint64_t seed = 0;
    int fd;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        if (read(fd, &seed, sizeof(seed)) != (ssize_t) sizeof(seed)) {
            seed = 0;
        }
        close(fd);
    }

    if (!seed) {
        seed = fallback_seed();
    }

    rng_state = seed;
}


uint32_t fs_rng_u32(void)
{
    uint64_t x;

    if (!rng_state) {
        seed_rng();
    }

    x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;

    return (uint32_t) ((x * 2685821657736338717ULL) >> 32);
}


unsigned long fs_rng_ulong(void)
{
#if ULONG_MAX > UINT32_MAX
    return ((unsigned long) fs_rng_u32() << 32) ^ fs_rng_u32();
#else
    return (unsigned long) fs_rng_u32();
#endif
}


uint32_t fs_rng_bounded(uint32_t bound)
{
    uint32_t threshold;
    uint32_t r;

    if (!bound) {
        return 0;
    }

    threshold = (uint32_t) -bound % bound;
    do {
        r = fs_rng_u32();
    } while (r < threshold);

    return r % bound;
}
