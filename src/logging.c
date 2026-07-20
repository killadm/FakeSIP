/*
 * logging.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "logging.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "globvar.h"

int fs_logger_setup(void)
{
    if (g_ctx.logpath) {
        g_ctx.logfp = fopen(g_ctx.logpath, "a");
        if (!g_ctx.logfp) {
            g_ctx.logfp = stderr;
            E("ERROR: fopen(): %s: %s", g_ctx.logpath, strerror(errno));
            return -1;
        }
    } else {
        g_ctx.logfp = stderr;
    }

    return 0;
}


void fs_logger_cleanup(void)
{
    if (g_ctx.logfp && g_ctx.logfp != stderr) {
        fclose(g_ctx.logfp);
        g_ctx.logfp = NULL;
    }
}


void fs_logger(const char *funcname, const char *filename, unsigned long line,
               int end, int flush, const char *fmt, ...)
{
    va_list args;
    time_t t;
    char time_buff[32];
    struct tm *tmi;

    t = time(NULL);
    tmi = localtime(&t);
    strftime(time_buff, sizeof(time_buff), "%Y-%m-%d %H:%M:%S", tmi);

    fprintf(g_ctx.logfp, "%19s [%13s:%03lu] ", time_buff, filename, line);
    va_start(args, fmt);
    vfprintf(g_ctx.logfp, fmt, args);
    va_end(args);
    fputc('\n', g_ctx.logfp);

    if (end) {
        fprintf(g_ctx.logfp, "%19s [%13s:%03lu]     at %s()\n", time_buff,
                filename, line, funcname);
    }
    if (flush || g_ctx.logfp == stderr) {
        fflush(g_ctx.logfp);
    }
}


void fs_logger_raw(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(g_ctx.logfp, fmt, args);
    va_end(args);
    fflush(g_ctx.logfp);
}
