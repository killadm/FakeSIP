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
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include "globvar.h"
#include "logging.h"

#define CMD_TIMEOUT_MS    30000
#define CMD_KILL_GRACE_MS 2000
#define CMD_POLL_MS       100

static long long monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        return (long long) time(NULL) * 1000;
    }

    return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


static int min_timeout_ms(long long deadline)
{
    long long now = monotonic_ms();
    long long remain = deadline - now;

    if (remain <= 0) {
        return 0;
    }
    if (remain > CMD_POLL_MS) {
        return CMD_POLL_MS;
    }
    return (int) remain;
}


static int wait_child_for(pid_t pid, int *status, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    int res, timeout;

    for (;;) {
        res = waitpid(pid, status, WNOHANG);
        if (res == pid) {
            return 0;
        }
        if (res < 0) {
            if (errno == EINTR) {
                continue;
            }
            E("ERROR: waitpid(): %s", strerror(errno));
            return -1;
        }

        timeout = min_timeout_ms(deadline);
        if (!timeout) {
            return 1;
        }

        res = poll(NULL, 0, timeout);
        if (res < 0 && errno != EINTR) {
            E("ERROR: poll(): %s", strerror(errno));
            return -1;
        }
    }
}


static int terminate_child(pid_t pid, int *status)
{
    int res;

    if (kill(pid, SIGTERM) < 0 && errno != ESRCH) {
        E("ERROR: kill(SIGTERM): %s", strerror(errno));
    }

    res = wait_child_for(pid, status, CMD_KILL_GRACE_MS);
    if (res == 0) {
        return -1;
    }

    if (kill(pid, SIGKILL) < 0 && errno != ESRCH) {
        E("ERROR: kill(SIGKILL): %s", strerror(errno));
    }

    res = wait_child_for(pid, status, CMD_KILL_GRACE_MS);
    if (res > 0) {
        E("ERROR: child process did not exit after SIGKILL: pid %llu",
          (unsigned long long) pid);
    } else if (res < 0 && errno != ECHILD) {
        E("ERROR: wait_child_for(): %s", strerror(errno));
    }

    return -1;
}


static int set_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        E("ERROR: fcntl(F_GETFL): %s", strerror(errno));
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        E("ERROR: fcntl(F_SETFL): %s", strerror(errno));
        return -1;
    }

    return 0;
}


static int wait_with_input(pid_t pid, int input_fd, const char *input,
                           int *status, const char *cmd)
{
    struct pollfd pfd;
    long long deadline = monotonic_ms() + CMD_TIMEOUT_MS;
    size_t input_len = input ? strlen(input) : 0;
    size_t written = 0;
    ssize_t n;
    int pipe_open = input_fd >= 0;
    int res, timeout;

    if (pipe_open && set_nonblock(input_fd) < 0) {
        close(input_fd);
        return terminate_child(pid, status);
    }

    for (;;) {
        res = waitpid(pid, status, WNOHANG);
        if (res == pid) {
            if (pipe_open) {
                close(input_fd);
            }
            return 0;
        }
        if (res < 0) {
            if (errno == EINTR) {
                continue;
            }
            E("ERROR: waitpid(): %s", strerror(errno));
            if (pipe_open) {
                close(input_fd);
            }
            return -1;
        }

        timeout = min_timeout_ms(deadline);
        if (!timeout) {
            E("ERROR: command timed out after %d ms: %s", CMD_TIMEOUT_MS, cmd);
            if (pipe_open) {
                close(input_fd);
            }
            return terminate_child(pid, status);
        }

        if (pipe_open && written < input_len) {
            pfd.fd = input_fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;

            res = poll(&pfd, 1, timeout);
            if (res < 0) {
                if (errno == EINTR) {
                    continue;
                }
                E("ERROR: poll(): %s", strerror(errno));
                close(input_fd);
                return terminate_child(pid, status);
            }
            if (!res) {
                continue;
            }

            if (pfd.revents & POLLOUT) {
                n = write(input_fd, input + written, input_len - written);
                if (n > 0) {
                    written += n;
                    continue;
                }
                if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                    continue;
                }
                if (n < 0 && errno == EPIPE) {
                    close(input_fd);
                    pipe_open = 0;
                    continue;
                }
                if (n < 0 && errno != EPIPE) {
                    E("ERROR: write(): %s", strerror(errno));
                    close(input_fd);
                    return terminate_child(pid, status);
                }
            }

            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close(input_fd);
                pipe_open = 0;
            }
        } else {
            if (pipe_open) {
                close(input_fd);
                pipe_open = 0;
            }

            res = poll(NULL, 0, timeout);
            if (res < 0 && errno != EINTR) {
                E("ERROR: poll(): %s", strerror(errno));
                return terminate_child(pid, status);
            }
        }
    }
}


int fs_execute_command(char **argv, int silent, char *input)
{
    int res, pipefd[2] = {-1, -1}, status, fd, i;
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
        pipefd[0] = -1;
    }

    res = wait_with_input(pid, pipefd[1], input, &status, argv[0]);
    pipefd[1] = -1;
    if (res < 0) {
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
