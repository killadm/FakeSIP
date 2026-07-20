/*
 * process.c - FakeSIP: https://github.com/MikeWang000000/FakeSIP
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
#include "process.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "globvar.h"
#include "logging.h"

int fs_execute_command(char **argv, int silent, char *input)
{
    int res, pipefd[2], status, fd, i;
    size_t input_len, written;
    ssize_t n;
    pid_t pid;

    if (input) {
        res = pipe(pipefd);
        if (res < 0) {
            E("ERROR: pipe(): %s", strerror(errno));
            return -1;
        }
    }

    pid = fork();
    if (pid < 0) {
        E("ERROR: fork(): %s", strerror(errno));
        if (input) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        return -1;
    }

    if (!pid) {
        fd = -1;

        if (silent) {
            fd = open("/dev/null", O_WRONLY);
            if (fd < 0) {
                E("ERROR: open(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
        } else if (g_ctx.logfp && g_ctx.logfp != stderr) {
            fd = fileno(g_ctx.logfp);
            if (fd < 0) {
                E("ERROR: fileno(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
        }

        if (fd >= 0) {
            res = dup2(fd, STDOUT_FILENO);
            if (res < 0) {
                E("ERROR: dup2(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
            res = dup2(fd, STDERR_FILENO);
            if (res < 0) {
                E("ERROR: dup2(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
            close(fd);
        }

        if (input) {
            close(pipefd[1]);
            res = dup2(pipefd[0], STDIN_FILENO);
            if (res < 0) {
                E("ERROR: dup2(): %s", strerror(errno));
                _exit(EXIT_FAILURE);
            }
            close(pipefd[0]);
        }

        res = setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        if (res < 0) {
            E("ERROR: setenv(): PATH: %s", strerror(errno));
            _exit(EXIT_FAILURE);
        }

        execvp(argv[0], argv);

        E("ERROR: execvp(): %s: %s", argv[0], strerror(errno));

        _exit(EXIT_FAILURE);
    }

    if (input) {
        close(pipefd[0]);
        input_len = strlen(input);
        for (written = 0; written < input_len; written += n) {
            n = write(pipefd[1], input + written, input_len - written);
            if (n < 0) {
                E("ERROR: write(): %s", strerror(errno));
                break;
            }
        }
        close(pipefd[1]);
    }

    if (waitpid(pid, &status, 0) < 0) {
        E("ERROR: waitpid(): %s", strerror(errno));
        goto child_failed;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

child_failed:
    if (!silent) {
        E_RAW("[*] failed command is: %s", argv[0]);
        for (i = 1; argv[i]; i++) {
            E_RAW(" %s", argv[i]);
        }
        E_RAW("\n");
    }

    return -1;
}
