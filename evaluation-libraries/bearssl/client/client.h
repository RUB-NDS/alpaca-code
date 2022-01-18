/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <arpa/inet.h>
#include <bearssl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


/*
 * Connect to the specified host and port. The connected socket is
 * returned, or -1 on error.
 */
static int
host_connect(const char *host, const char *port) {
    struct addrinfo hints, *si, *p;
    int fd;
    int err;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &si);
    if (err != 0) {
        fprintf(stderr, "ERROR: getaddrinfo(): %s\n",
                gai_strerror(err));
        return -1;
    }
    fd = -1;
    for (p = si; p != NULL; p = p->ai_next) {
        struct sockaddr *sa;
        void *addr;
        char tmp[INET6_ADDRSTRLEN + 50];

        sa = (struct sockaddr *)p->ai_addr;
        if (sa->sa_family == AF_INET) {
            addr = &((struct sockaddr_in *)sa)->sin_addr;
        } else if (sa->sa_family == AF_INET6) {
            addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
        } else {
            addr = NULL;
        }
        if (addr != NULL) {
            inet_ntop(p->ai_family, addr, tmp, sizeof tmp);
        } else {
            sprintf(tmp, "<unknown family: %d>",
                    (int)sa->sa_family);
        }
        //fprintf(stderr, "connecting to: %s\n", tmp);
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            perror("socket()");
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
            perror("connect()");
            close(fd);
            continue;
        }
        break;
    }
    if (p == NULL) {
        freeaddrinfo(si);
        fprintf(stderr, "ERROR: failed to connect\n");
        return -1;
    }
    freeaddrinfo(si);
    //fprintf(stderr, "connected.\n");
    return fd;
}

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int
sock_read(void *ctx, unsigned char *buf, size_t len) {
    for (;;) {
        ssize_t rlen;

        rlen = read(*(int *)ctx, buf, len);
        if (rlen <= 0) {
            if (rlen < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        return (int)rlen;
    }
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len) {
    for (;;) {
        ssize_t wlen;

        wlen = write(*(int *)ctx, buf, len);
        if (wlen <= 0) {
            if (wlen < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        return (int)wlen;
    }
}