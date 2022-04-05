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



#include "bearssl.h"

/* from bearssl-0.6/src/ssl/ssl_hashes.c */
int br_ssl_choose_hash(unsigned bf) {
    static const unsigned char pref[] = {
        br_sha256_ID, br_sha384_ID, br_sha512_ID,
        br_sha224_ID, br_sha1_ID};
    size_t u;

    for (u = 0; u < sizeof pref; u++) {
        int x;

        x = pref[u];
        if ((bf >> x) & 1) {
            return x;
        }
    }
    return 0;
}

/* from bearssl-0.6/src/ssl/br_ssl_server_set_single_rsa.c */
static int
choose(const br_ssl_server_policy_class **pctx,
          const br_ssl_server_context *cc,
          br_ssl_server_choices *choices) {
    br_ssl_server_policy_rsa_context *pc;
    const br_suite_translated *st;
    size_t u, st_num;
    unsigned hash_id;
    int fh;

    /* verify SNI extension */
    const char *servername_received = br_ssl_engine_get_server_name(&cc->eng);
    if (strcmp("tls-server.com", servername_received) != 0) {
        fprintf(stderr, "\n Invalid SNI received: %s\n", servername_received);
        return 0;
    } else {
        printf("\n SNI received: %s\n", servername_received);
    }

    //printf("workign fine %s \n", name);

    pc = (br_ssl_server_policy_rsa_context *)pctx;
    st = br_ssl_server_get_client_suites(cc, &st_num);
    if (cc->eng.session.version < BR_TLS12) {
        hash_id = 0;
        fh = 1;
    } else {
        hash_id = br_ssl_choose_hash(
            br_ssl_server_get_client_hashes(cc));
        fh = (hash_id != 0);
    }
    choices->chain = pc->chain;
    choices->chain_len = pc->chain_len;
    for (u = 0; u < st_num; u++) {
        unsigned tt;

        tt = st[u][1];
        switch (tt >> 12) {
            case BR_SSLKEYX_RSA:
                if ((pc->allowed_usages & BR_KEYTYPE_KEYX) != 0) {
                    choices->cipher_suite = st[u][0];
                    return 1;
                }
                break;
            case BR_SSLKEYX_ECDHE_RSA:
                if ((pc->allowed_usages & BR_KEYTYPE_SIGN) != 0 && fh) {
                    choices->cipher_suite = st[u][0];
                    choices->algo_id = hash_id + 0xFF00;
                    return 1;
                }
                break;
        }
    }
    return 0;
}

static uint32_t
do_keyx(const br_ssl_server_policy_class **pctx,
           unsigned char *data, size_t *len) {
    br_ssl_server_policy_rsa_context *pc;

    pc = (br_ssl_server_policy_rsa_context *)pctx;
    return br_rsa_ssl_decrypt(pc->irsacore, pc->sk, data, *len);
}

/*
 * OID for hash functions in RSA signatures.
 */
static const unsigned char HASH_OID_SHA1[] = {
    0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A};

static const unsigned char HASH_OID_SHA224[] = {
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04};

static const unsigned char HASH_OID_SHA256[] = {
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};

static const unsigned char HASH_OID_SHA384[] = {
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};

static const unsigned char HASH_OID_SHA512[] = {
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};

static const unsigned char *HASH_OID[] = {
    HASH_OID_SHA1,
    HASH_OID_SHA224,
    HASH_OID_SHA256,
    HASH_OID_SHA384,
    HASH_OID_SHA512};

static size_t
do_sign(const br_ssl_server_policy_class **pctx,
           unsigned algo_id, unsigned char *data, size_t hv_len, size_t len) {
    br_ssl_server_policy_rsa_context *pc;
    unsigned char hv[64];
    size_t sig_len;
    const unsigned char *hash_oid;

    pc = (br_ssl_server_policy_rsa_context *)pctx;
    memcpy(hv, data, hv_len);
    algo_id &= 0xFF;
    if (algo_id == 0) {
        hash_oid = NULL;
    } else if (algo_id >= 2 && algo_id <= 6) {
        hash_oid = HASH_OID[algo_id - 2];
    } else {
        return 0;
    }
    sig_len = (pc->sk->n_bitlen + 7) >> 3;
    if (len < sig_len) {
        return 0;
    }
    return pc->irsasign(hash_oid, hv, hv_len, pc->sk, data) ? sig_len : 0;
}

/*
 * This sample code can use three possible certificate chains:
 * -- A full-RSA chain (server key is RSA, certificates are signed with RSA)
 * -- A full-EC chain (server key is EC, certificates are signed with ECDSA)
 * -- A mixed chain (server key is EC, certificates are signed with RSA)
 *
 * The macros below define which chain is selected. This impacts the list
 * of supported cipher suites.
 */

#if !(SERVER_RSA || SERVER_EC || SERVER_MIXED)
#define SERVER_RSA 1
#define SERVER_EC 0
#define SERVER_MIXED 0
#endif

/*
 * Create a server socket bound to the specified host and port. If 'host'
 * is NULL, this will bind "generically" (all addresses).
 *
 * Returned value is the server socket descriptor, or -1 on error.
 */
static int
host_bind(const char *host, const char *port) {
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
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
        size_t sa_len;
        void *addr;
        char tmp[INET6_ADDRSTRLEN + 50];
        int opt;

        sa = (struct sockaddr *)p->ai_addr;
        if (sa->sa_family == AF_INET) {
            sa4 = *(struct sockaddr_in *)sa;
            sa = (struct sockaddr *)&sa4;
            sa_len = sizeof sa4;
            addr = &sa4.sin_addr;
            if (host == NULL) {
                sa4.sin_addr.s_addr = INADDR_ANY;
            }
        } else if (sa->sa_family == AF_INET6) {
            sa6 = *(struct sockaddr_in6 *)sa;
            sa = (struct sockaddr *)&sa6;
            sa_len = sizeof sa6;
            addr = &sa6.sin6_addr;
            if (host == NULL) {
                sa6.sin6_addr = in6addr_any;
            }
        } else {
            addr = NULL;
            sa_len = p->ai_addrlen;
        }
        if (addr != NULL) {
            inet_ntop(p->ai_family, addr, tmp, sizeof tmp);
        } else {
            sprintf(tmp, "<unknown family: %d>",
                    (int)sa->sa_family);
        }
        //fprintf(stderr, "binding to: %s\n", tmp);
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            perror("socket()");
            continue;
        }
        opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
        opt = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt);
        if (bind(fd, sa, sa_len) < 0) {
            perror("bind()");
            close(fd);
            continue;
        }
        break;
    }
    if (p == NULL) {
        freeaddrinfo(si);
        fprintf(stderr, "ERROR: failed to bind\n");
        return -1;
    }
    freeaddrinfo(si);
    if (listen(fd, 5) < 0) {
        perror("listen()");
        close(fd);
        return -1;
    }
    //printf(stderr, "bound.\n");
    return fd;
}

/*
 * Accept a single client on the provided server socket. This is blocking.
 * On error, this returns -1.
 */
static int
accept_client(int server_fd) {
    int fd;
    struct sockaddr sa;
    socklen_t sa_len;
    char tmp[INET6_ADDRSTRLEN + 50];
    const char *name;

    sa_len = sizeof sa;
    fd = accept(server_fd, &sa, &sa_len);
    if (fd < 0) {
        perror("accept()");
        return -1;
    }
    name = NULL;
    switch (sa.sa_family) {
        case AF_INET:
            name = inet_ntop(AF_INET,
                             &((struct sockaddr_in *)&sa)->sin_addr,
                             tmp, sizeof tmp);
            break;
        case AF_INET6:
            name = inet_ntop(AF_INET,
                             &((struct sockaddr_in *)&sa)->sin_addr,
                             tmp, sizeof tmp);
            break;
    }
    if (name == NULL) {
        sprintf(tmp, "<unknown: %lu>", (unsigned long)sa.sa_family);
        name = tmp;
    }
    //fprintf(stderr, "accepting connection from: %s\n", name);
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
