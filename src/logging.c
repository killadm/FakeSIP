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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "globvar.h"

#define LOG_QUEUE_SIZE       128
#define LOG_MSG_SIZE         512
#define LOG_FILE_BUFFER_SIZE (16 * 1024)
#define LOG_SYNC_WAIT_MS     10
#define LOG_ROTATE_TRIES     1000

struct log_msg {
    char data[LOG_MSG_SIZE];
    size_t len;
    int force_flush;
};

static pthread_t logger_tid;
static pthread_mutex_t logger_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t logger_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t logger_not_full = PTHREAD_COND_INITIALIZER;
static struct log_msg log_queue[LOG_QUEUE_SIZE];
static char log_file_buffer[LOG_FILE_BUFFER_SIZE];
static size_t log_head, log_tail, log_count;
static unsigned long long dropped_info;
static time_t cached_time = (time_t) -1;
static time_t last_flush = (time_t) -1;
static off_t current_size;
static int logger_async, logger_stop;

static const char *logger_time(time_t t)
{
    static char cached_time_buff[32];
    struct tm tmi;

    if (t == cached_time) {
        return cached_time_buff;
    }

    if (!localtime_r(&t, &tmi) ||
        !strftime(cached_time_buff, sizeof(cached_time_buff),
                  "%Y-%m-%d %H:%M:%S", &tmi)) {
        snprintf(cached_time_buff, sizeof(cached_time_buff), "%lld",
                 (long long) t);
    }

    cached_time = t;

    return cached_time_buff;
}


static void make_timestamp(time_t t, const char *fmt, char *buf,
                           size_t buf_size)
{
    struct tm tmi;

    if (!localtime_r(&t, &tmi) || !strftime(buf, buf_size, fmt, &tmi)) {
        snprintf(buf, buf_size, "%lld", (long long) t);
    }
}


static int split_log_path(char *dir, size_t dir_size, char *base,
                          size_t base_size)
{
    const char *slash, *path;
    size_t dir_len, base_len;

    path = g_ctx.logpath;
    slash = strrchr(path, '/');
    if (!slash) {
        dir_len = 1;
        base_len = strlen(path);
        if (dir_len >= dir_size || base_len >= base_size) {
            return -1;
        }
        strcpy(dir, ".");
        strcpy(base, path);
        return 0;
    }

    dir_len = slash == path ? 1 : (size_t) (slash - path);
    base_len = strlen(slash + 1);
    if (!base_len || dir_len >= dir_size || base_len >= base_size) {
        return -1;
    }

    memcpy(dir, path, dir_len);
    dir[dir_len] = '\0';
    strcpy(base, slash + 1);

    return 0;
}


static int rotate_name_matches(const char *base, const char *name)
{
    const char *p;
    size_t i, base_len;

    base_len = strlen(base);
    if (strncmp(name, base, base_len) || name[base_len] != '.') {
        return 0;
    }

    p = name + base_len + 1;
    if (strlen(p) < 15) {
        return 0;
    }
    for (i = 0; i < 8; i++) {
        if (!isdigit((unsigned char) p[i])) {
            return 0;
        }
    }
    if (p[8] != '-') {
        return 0;
    }
    for (i = 9; i < 15; i++) {
        if (!isdigit((unsigned char) p[i])) {
            return 0;
        }
    }
    if (!p[15]) {
        return 1;
    }
    if (p[15] != '.' || !p[16]) {
        return 0;
    }
    for (i = 16; p[i]; i++) {
        if (!isdigit((unsigned char) p[i])) {
            return 0;
        }
    }

    return 1;
}


static int rotate_suffix(const char *base, const char *name)
{
    const char *p;

    p = name + strlen(base) + 1 + 15;
    if (!*p) {
        return 0;
    }

    return atoi(p + 1);
}


static int rotate_name_cmp(const char *base, const char *a, const char *b)
{
    int res, suffix_a, suffix_b;
    size_t prefix_len;

    prefix_len = strlen(base) + 1;
    res = strncmp(a + prefix_len, b + prefix_len, 15);
    if (res) {
        return res;
    }

    suffix_a = rotate_suffix(base, a);
    suffix_b = rotate_suffix(base, b);
    if (suffix_a < suffix_b) {
        return -1;
    } else if (suffix_a > suffix_b) {
        return 1;
    }

    return 0;
}


static int make_dir_path(char *path, size_t path_size, const char *dir,
                         const char *name)
{
    int res;

    if (!strcmp(dir, "/")) {
        res = snprintf(path, path_size, "/%s", name);
    } else {
        res = snprintf(path, path_size, "%s/%s", dir, name);
    }

    if (res < 0 || (size_t) res >= path_size) {
        return -1;
    }

    return 0;
}


static void cleanup_rotated_logs(void)
{
    DIR *dp;
    struct dirent *ent;
    int cnt, found;
    char dir[PATH_MAX], base[PATH_MAX], oldest[PATH_MAX], oldpath[PATH_MAX];

    if (!g_ctx.logpath ||
        split_log_path(dir, sizeof(dir), base, sizeof(base)) < 0) {
        return;
    }

    for (;;) {
        dp = opendir(dir);
        if (!dp) {
            return;
        }

        cnt = 0;
        found = 0;
        oldest[0] = '\0';
        while ((ent = readdir(dp))) {
            if (!rotate_name_matches(base, ent->d_name)) {
                continue;
            }
            cnt++;
            if (!found || rotate_name_cmp(base, ent->d_name, oldest) < 0) {
                if (strlen(ent->d_name) >= sizeof(oldest)) {
                    continue;
                }
                strcpy(oldest, ent->d_name);
                found = 1;
            }
        }
        closedir(dp);

        if (cnt <= (int) g_ctx.log_rotate_count || !found) {
            return;
        }

        if (make_dir_path(oldpath, sizeof(oldpath), dir, oldest) < 0 ||
            unlink(oldpath) < 0) {
            return;
        }
    }
}


static int open_log_file(const char *mode)
{
    int fd;
    struct stat st;

    g_ctx.logfp = fopen(g_ctx.logpath, mode);
    if (!g_ctx.logfp) {
        return -1;
    }

    setvbuf(g_ctx.logfp, log_file_buffer, _IOFBF, sizeof(log_file_buffer));

    current_size = 0;
    fd = fileno(g_ctx.logfp);
    if (fd >= 0 && fstat(fd, &st) == 0) {
        current_size = st.st_size;
    }

    return 0;
}


static void logger_warning(const char *fmt, ...)
{
    FILE *fp;
    va_list args;
    time_t t;
    char buff[LOG_MSG_SIZE], tbuf[32];
    int len;

    t = time(NULL);
    make_timestamp(t, "%Y-%m-%d %H:%M:%S", tbuf, sizeof(tbuf));
    len = snprintf(buff, sizeof(buff), "%19s [%13s:%03d] WARNING: ", tbuf,
                   "logging.c", 0);
    if (len < 0) {
        return;
    }

    if ((size_t) len >= sizeof(buff)) {
        len = sizeof(buff) - 1;
    }

    va_start(args, fmt);
    len += vsnprintf(buff + len, sizeof(buff) - (size_t) len, fmt, args);
    va_end(args);
    if (len < 0) {
        return;
    }
    if ((size_t) len >= sizeof(buff) - 1) {
        len = sizeof(buff) - 2;
    }
    buff[len++] = '\n';

    fp = g_ctx.logfp ? g_ctx.logfp : stderr;
    if (fwrite(buff, 1, (size_t) len, fp) == (size_t) len && fp != stderr) {
        current_size += len;
    }
    fflush(fp);
}


static int make_rotate_path(char *path, size_t path_size)
{
    time_t t;
    int res, i;
    char ts[32];

    t = time(NULL);
    make_timestamp(t, "%Y%m%d-%H%M%S", ts, sizeof(ts));

    res = snprintf(path, path_size, "%s.%s", g_ctx.logpath, ts);
    if (res < 0 || (size_t) res >= path_size) {
        return -1;
    }
    if (access(path, F_OK) != 0) {
        return 0;
    }

    for (i = 1; i < LOG_ROTATE_TRIES; i++) {
        res = snprintf(path, path_size, "%s.%s.%d", g_ctx.logpath, ts, i);
        if (res < 0 || (size_t) res >= path_size) {
            return -1;
        }
        if (access(path, F_OK) != 0) {
            return 0;
        }
    }

    return -1;
}


static void rotate_if_needed(size_t add_len)
{
    char rotate_path[PATH_MAX];

    if (!g_ctx.logpath || !g_ctx.logfp || g_ctx.logfp == stderr ||
        !g_ctx.log_max_size ||
        current_size + (off_t) add_len <= (off_t) g_ctx.log_max_size) {
        return;
    }

    fflush(g_ctx.logfp);
    fclose(g_ctx.logfp);
    g_ctx.logfp = NULL;

    if (!g_ctx.log_rotate_count) {
        if (open_log_file("w") < 0) {
            g_ctx.logfp = stderr;
            logger_warning("failed to reopen log file: %s: %s", g_ctx.logpath,
                           strerror(errno));
        }
        return;
    }

    if (make_rotate_path(rotate_path, sizeof(rotate_path)) < 0 ||
        rename(g_ctx.logpath, rotate_path) < 0) {
        if (open_log_file("a") < 0) {
            g_ctx.logfp = stderr;
        }
        logger_warning("failed to rotate log file: %s", strerror(errno));
        return;
    }

    cleanup_rotated_logs();

    if (open_log_file("a") < 0) {
        g_ctx.logfp = stderr;
        logger_warning("failed to reopen log file: %s: %s", g_ctx.logpath,
                       strerror(errno));
    }
}


static void write_direct(const char *data, size_t len, int force_flush)
{
    FILE *fp;
    time_t t;

    fp = g_ctx.logfp ? g_ctx.logfp : stderr;
    if (fp != stderr) {
        rotate_if_needed(len);
        fp = g_ctx.logfp ? g_ctx.logfp : stderr;
    }

    if (fwrite(data, 1, len, fp) == len && fp != stderr) {
        current_size += len;
    }

    t = time(NULL);
    if (force_flush || fp == stderr || t != last_flush) {
        fflush(fp);
        last_flush = t;
    }
}


static void write_drop_report(unsigned long long cnt)
{
    char buff[LOG_MSG_SIZE];
    char tbuf[32];
    time_t t;
    int len;

    t = time(NULL);
    make_timestamp(t, "%Y-%m-%d %H:%M:%S", tbuf, sizeof(tbuf));
    len = snprintf(buff, sizeof(buff),
                   "%19s [%13s:%03d] dropped %llu info log messages\n", tbuf,
                   "logging.c", 0, cnt);
    if (len < 0) {
        return;
    }
    if ((size_t) len >= sizeof(buff)) {
        len = sizeof(buff) - 1;
    }

    write_direct(buff, (size_t) len, 1);
}


static void *logger_loop(void *arg)
{
    struct log_msg msg;
    unsigned long long dropped;
    int have_msg;

    (void) arg;

    for (;;) {
        pthread_mutex_lock(&logger_mutex);
        while (!log_count && !logger_stop) {
            pthread_cond_wait(&logger_not_empty, &logger_mutex);
        }

        have_msg = 0;
        dropped = 0;
        if (log_count) {
            msg = log_queue[log_head];
            log_head = (log_head + 1) % LOG_QUEUE_SIZE;
            log_count--;
            have_msg = 1;
            pthread_cond_signal(&logger_not_full);
        }
        if (dropped_info && log_count < LOG_QUEUE_SIZE) {
            dropped = dropped_info;
            dropped_info = 0;
        }
        if (!have_msg && logger_stop) {
            pthread_mutex_unlock(&logger_mutex);
            break;
        }
        pthread_mutex_unlock(&logger_mutex);

        if (dropped) {
            write_drop_report(dropped);
        }
        if (have_msg) {
            write_direct(msg.data, msg.len, msg.force_flush);
        }
    }

    pthread_mutex_lock(&logger_mutex);
    dropped = dropped_info;
    dropped_info = 0;
    pthread_mutex_unlock(&logger_mutex);
    if (dropped) {
        write_drop_report(dropped);
    }

    return NULL;
}


static void fallback_stderr(const char *data, size_t len)
{
    fwrite(data, 1, len, stderr);
    fflush(stderr);
}


static void add_ms(struct timespec *ts, long ms)
{
    ts->tv_nsec += ms * 1000000L;
    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}


static void enqueue_or_write(const char *data, size_t len, int force_flush,
                             int info)
{
    struct timespec deadline;
    int res;

    if (!logger_async) {
        write_direct(data, len, force_flush);
        return;
    }

    pthread_mutex_lock(&logger_mutex);
    if (log_count == LOG_QUEUE_SIZE && info) {
        dropped_info++;
        pthread_mutex_unlock(&logger_mutex);
        return;
    }

    if (log_count == LOG_QUEUE_SIZE) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        add_ms(&deadline, LOG_SYNC_WAIT_MS);
        while (log_count == LOG_QUEUE_SIZE && !logger_stop) {
            res = pthread_cond_timedwait(&logger_not_full, &logger_mutex,
                                         &deadline);
            if (res == ETIMEDOUT) {
                break;
            }
        }
    }

    if (log_count == LOG_QUEUE_SIZE || logger_stop) {
        pthread_mutex_unlock(&logger_mutex);
        fallback_stderr(data, len);
        return;
    }

    memcpy(log_queue[log_tail].data, data, len);
    log_queue[log_tail].len = len;
    log_queue[log_tail].force_flush = force_flush;
    log_tail = (log_tail + 1) % LOG_QUEUE_SIZE;
    log_count++;
    pthread_cond_signal(&logger_not_empty);
    pthread_mutex_unlock(&logger_mutex);
}


static void append_format(char *buf, size_t *len, const char *fmt, ...)
{
    va_list args;
    int res;
    size_t avail;

    if (*len >= LOG_MSG_SIZE - 1) {
        return;
    }

    avail = LOG_MSG_SIZE - *len;
    va_start(args, fmt);
    res = vsnprintf(buf + *len, avail, fmt, args);
    va_end(args);
    if (res < 0) {
        return;
    }

    if ((size_t) res >= avail) {
        *len = LOG_MSG_SIZE - 1;
    } else {
        *len += (size_t) res;
    }
}


static void append_vformat(char *buf, size_t *len, const char *fmt,
                           va_list args)
{
    int res;
    size_t avail;

    if (*len >= LOG_MSG_SIZE - 1) {
        return;
    }

    avail = LOG_MSG_SIZE - *len;
    res = vsnprintf(buf + *len, avail, fmt, args);
    if (res < 0) {
        return;
    }

    if ((size_t) res >= avail) {
        *len = LOG_MSG_SIZE - 1;
    } else {
        *len += (size_t) res;
    }
}


static void ensure_newline(char *buf, size_t *len)
{
    if (*len && buf[*len - 1] == '\n') {
        return;
    }

    if (*len >= LOG_MSG_SIZE - 1) {
        if (*len >= 4) {
            buf[*len - 4] = '.';
            buf[*len - 3] = '.';
            buf[*len - 2] = '.';
        }
        buf[*len - 1] = '\n';
        return;
    }

    buf[(*len)++] = '\n';
    buf[*len] = '\0';
}


static void logger_vmsg(const char *funcname, const char *filename,
                        unsigned long line, int end, int info, const char *fmt,
                        va_list args)
{
    char buff[LOG_MSG_SIZE];
    const char *time_str;
    size_t len;
    time_t t;

    t = time(NULL);
    time_str = logger_time(t);

    len = 0;
    append_format(buff, &len, "%19s [%13s:%03lu] ", time_str, filename, line);
    append_vformat(buff, &len, fmt, args);
    ensure_newline(buff, &len);

    if (end) {
        append_format(buff, &len, "%19s [%13s:%03lu]     at %s()\n", time_str,
                      filename, line, funcname);
        ensure_newline(buff, &len);
    }

    enqueue_or_write(buff, len, end, info);
}


int fs_logger_setup(void)
{
    int res;

    cached_time = (time_t) -1;
    last_flush = (time_t) -1;
    current_size = 0;
    logger_stop = 0;
    logger_async = 0;
    log_head = log_tail = log_count = 0;
    dropped_info = 0;

    if (g_ctx.logpath) {
        if (open_log_file("a") < 0) {
            g_ctx.logfp = stderr;
            E("ERROR: fopen(): %s: %s", g_ctx.logpath, strerror(errno));
            return -1;
        }

        res = pthread_create(&logger_tid, NULL, logger_loop, NULL);
        if (res) {
            logger_async = 0;
            E("WARNING: pthread_create(): %s", strerror(res));
            return 0;
        }
        logger_async = 1;
    } else {
        g_ctx.logfp = stderr;
    }

    return 0;
}


void fs_logger_cleanup(void)
{
    if (logger_async) {
        pthread_mutex_lock(&logger_mutex);
        logger_stop = 1;
        pthread_cond_signal(&logger_not_empty);
        pthread_mutex_unlock(&logger_mutex);
        pthread_join(logger_tid, NULL);
        logger_async = 0;
    }

    if (g_ctx.logfp) {
        fflush(g_ctx.logfp);
    }

    if (g_ctx.logfp && g_ctx.logfp != stderr) {
        fclose(g_ctx.logfp);
        g_ctx.logfp = NULL;
    }
}


void fs_logger(const char *funcname, const char *filename, unsigned long line,
               int end, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    logger_vmsg(funcname, filename, line, end, 0, fmt, args);
    va_end(args);
}


void fs_logger_info(const char *funcname, const char *filename,
                    unsigned long line, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    logger_vmsg(funcname, filename, line, 0, 1, fmt, args);
    va_end(args);
}


void fs_logger_raw(const char *fmt, ...)
{
    char buff[LOG_MSG_SIZE];
    va_list args;
    size_t len;

    len = 0;
    va_start(args, fmt);
    append_vformat(buff, &len, fmt, args);
    va_end(args);
    enqueue_or_write(buff, len, 0, 0);
}
