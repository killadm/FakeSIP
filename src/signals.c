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


int fs_kill_running(int signal)
{
    int res, matched, err;
    ssize_t len;
    DIR *procfs;
    struct dirent *entry;
    pid_t pid, self_pid;
    char self_path[PATH_MAX], proc_path[PATH_MAX], exe_path[PATH_MAX];

    self_pid = getpid();

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
