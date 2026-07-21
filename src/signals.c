/*
 * signals.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "signals.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"

#define PIDFILE_PATH "/var/run/fakesip.pid"

static volatile sig_atomic_t exit_requested = 0;

static void signal_handler(int sig)
{
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            exit_requested = 1;
            break;
        default:
            break;
    }
}


int fs_signal_setup(void)
{
    struct sigaction sa;
    int res;

    exit_requested = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;

    res = sigaction(SIGPIPE, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    res = sigaction(SIGHUP, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    sa.sa_handler = signal_handler;

    res = sigaction(SIGINT, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    res = sigaction(SIGTERM, &sa, NULL);
    if (res < 0) {
        E("ERROR: sigaction(): %s", strerror(errno));
        return -1;
    }

    return 0;
}


int fs_signal_exit_requested(void)
{
    return exit_requested != 0;
}


static int read_proc_comm(pid_t pid, char *buf, size_t len)
{
    FILE *fp;
    char path[PATH_MAX];
    char *newline;
    int res;

    if (!pid) {
        res = snprintf(path, sizeof(path), "/proc/self/comm");
    } else {
        res = snprintf(path, sizeof(path), "/proc/%llu/comm",
                       (unsigned long long) pid);
    }
    if (res < 0 || (size_t) res >= sizeof(path)) {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    if (!fgets(buf, len, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    newline = strchr(buf, '\n');
    if (newline) {
        *newline = 0;
    }

    return 0;
}


static int pid_matches_self_comm(pid_t pid)
{
    char self_comm[64], proc_comm[64];

    if (read_proc_comm(0, self_comm, sizeof(self_comm)) < 0 ||
        read_proc_comm(pid, proc_comm, sizeof(proc_comm)) < 0) {
        return 0;
    }

    return strcmp(self_comm, proc_comm) == 0;
}


static int read_pidfile(pid_t *pid)
{
    FILE *fp;
    char buf[64];
    char *end;
    unsigned long long value;

    fp = fopen(PIDFILE_PATH, "r");
    if (!fp) {
        if (errno == ENOENT) {
            return 1;
        }
        E("ERROR: fopen(): %s: %s", PIDFILE_PATH, strerror(errno));
        return -1;
    }

    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return 1;
    }
    fclose(fp);

    errno = 0;
    value = strtoull(buf, &end, 10);
    if (errno || end == buf || value <= 1 || value > INT_MAX) {
        return 1;
    }

    *pid = (pid_t) value;
    return 0;
}


static int process_exists(pid_t pid)
{
    if (kill(pid, 0) == 0) {
        return 1;
    }

    if (errno == EPERM) {
        return 1;
    }

    return 0;
}


static void unlink_pidfile(void)
{
    if (unlink(PIDFILE_PATH) < 0 && errno != ENOENT) {
        E("WARNING: unlink(): %s: %s", PIDFILE_PATH, strerror(errno));
    }
}


int fs_pidfile_create(void)
{
    FILE *fp;
    pid_t pid;
    int res;

    res = read_pidfile(&pid);
    if (res < 0) {
        return -1;
    }
    if (!res) {
        if (pid != getpid() && process_exists(pid) &&
            pid_matches_self_comm(pid)) {
            E("ERROR: another FakeSIP process is running: pid %llu",
              (unsigned long long) pid);
            return -1;
        }
        unlink_pidfile();
    }

    fp = fopen(PIDFILE_PATH, "w");
    if (!fp) {
        E("ERROR: fopen(): %s: %s", PIDFILE_PATH, strerror(errno));
        return -1;
    }

    if (fprintf(fp, "%llu\n", (unsigned long long) getpid()) < 0) {
        E("ERROR: fprintf(): %s", strerror(errno));
        fclose(fp);
        unlink_pidfile();
        return -1;
    }

    if (fclose(fp) < 0) {
        E("ERROR: fclose(): %s: %s", PIDFILE_PATH, strerror(errno));
        unlink_pidfile();
        return -1;
    }

    return 0;
}


void fs_pidfile_remove(void)
{
    pid_t pid;

    if (read_pidfile(&pid) == 0 && pid != getpid()) {
        return;
    }

    unlink_pidfile();
}


static int kill_pidfile_process(int signal)
{
    int res;
    pid_t pid, self_pid;

    self_pid = getpid();

    res = read_pidfile(&pid);
    if (res != 0) {
        return -1;
    }

    if (pid == self_pid) {
        if (signal) {
            unlink_pidfile();
        }
        return -1;
    }

    if (pid <= 1) {
        unlink_pidfile();
        return -1;
    }

    if (!process_exists(pid)) {
        unlink_pidfile();
        return -1;
    }

    if (!pid_matches_self_comm(pid)) {
        unlink_pidfile();
        return -1;
    }

    if (signal && kill(pid, signal) < 0) {
        E("ERROR: kill(): %llu: %s", (unsigned long long) pid,
          strerror(errno));
        return -1;
    }

    return 0;
}


int fs_kill_running(int signal)
{
    int res, matched, err;
    ssize_t len;
    DIR *procfs;
    struct dirent *entry;
    pid_t pid, self_pid;
    char self_path[PATH_MAX], proc_path[PATH_MAX], exe_path[PATH_MAX];

    self_pid = getpid();

    res = kill_pidfile_process(signal);
    if (res == 0) {
        return 0;
    }

    len = readlink("/proc/self/exe", self_path, sizeof(self_path));
    if (len < 0 || (size_t) len >= sizeof(self_path)) {
        E("ERROR: readlink(): /proc/self/exe: %s", strerror(errno));
        return -1;
    }
    self_path[len] = 0;

    procfs = opendir("/proc");
    if (!procfs) {
        E("ERROR: opendir(): /proc: %s", strerror(errno));
        return -1;
    }

    matched = err = 0;
    while ((entry = readdir(procfs))) {
        pid = strtoull(entry->d_name, NULL, 0);
        if (pid <= 1 || pid == self_pid) {
            continue;
        }

        res = snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe",
                       entry->d_name);
        if (res < 0 || (size_t) res >= sizeof(exe_path)) {
            continue;
        }

        len = readlink(exe_path, proc_path, sizeof(proc_path));
        if (len < 0 || (size_t) len >= sizeof(self_path)) {
            continue;
        }
        proc_path[len] = 0;

        if (strcmp(self_path, proc_path) == 0) {
            matched = 1;

            if (signal) {
                res = kill(pid, signal);
                if (res < 0) {
                    E("ERROR: kill(): %llu: %s", (unsigned long long) pid,
                      strerror(errno));
                    err = 1;
                }
            }
        }
    }

    res = closedir(procfs);
    if (res < 0) {
        E("ERROR: closedir(): %s", strerror(errno));
        err = 1;
    }

    if (matched && !err) {
        return 0;
    }

    return -1;
}
