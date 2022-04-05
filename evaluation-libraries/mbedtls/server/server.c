/*
 *  SSL server demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/x509.h"

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;

// needs to return 0 if a valid SNI was found and set the correct certificate
int sni_callback(void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len) {
    if (strcmp((const char *)name, (const char *)p_info) == 0) {
        mbedtls_printf("VALID SNI: %s \n", name);
        mbedtls_ssl_set_hs_own_cert(ssl, &srvcert, &pkey);
        return 0;
    } else {
        mbedtls_printf("INVALID SNI: %s \n", name);
        return -1;
    }
}

int main(int argc, char **argv) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    char *servername = "tls-server.com";
    char *port = "4433";
    const char *alpn[] = {"http/1.1", NULL};
    char *cert = "/etc/ssl/cert-data/tls-server.com-chain.crt";
    char *key = "/etc/ssl/cert-data/tls-server.com.key";

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:k:p")) != -1) {
        switch (opt) {
            case 'a':
                alpn[0] = optarg;
                break;
            case 's':
                servername = optarg;
                break;
            case 'k':
                key = optarg;
                break;
            case 'p':
                port = optarg;
                break;
            case 'c':
                cert = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-h ip] [-p port] [-c certificate] \n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    printf("Parameters alpn=%s servername=%s cert=%s key=%s port=%s \n", alpn[0], servername, cert, key, port);

    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // 1. Load the certificates and private RSA key
    ret = mbedtls_x509_crt_parse_file(&srvcert, cert);
    if (ret != 0) {
        mbedtls_printf("mbedtls_x509_crt_parse_file returned %d\n", ret);
        goto exit;
    }
    ret = mbedtls_pk_parse_keyfile(&pkey, key, NULL);
    if (ret != 0) {
        mbedtls_printf("mbedtls_pk_parse_keyfile returned %d\n", ret);
        goto exit;
    }

    //  2. Setup the listening TCP socket
    if ((ret = mbedtls_net_bind(&listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf("mbedtls_net_bind returned %d\n", ret);
        goto exit;
    }

    // 3. Seed the RNG
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    // 4. Setup SSL config
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf("mbedtls_ssl_config_defaults returned %d\n", ret);
        goto exit;
    }

    // Set ALPN
    if ((ret = mbedtls_ssl_conf_alpn_protocols(&conf, alpn)) != 0) {
        mbedtls_printf("mbedtls_ssl_conf_alpn_protocols returned %d\n", ret);
        goto exit;
    }

    // set SNI callback function
    mbedtls_ssl_conf_sni(&conf, sni_callback, servername);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        mbedtls_printf("mbedtls_ssl_conf_own_cert returned %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf("mbedtls_ssl_setup returned %d\n", ret);
        goto exit;
    }

reset:
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n", ret, error_buf);
    }
    mbedtls_net_free(&client_fd);
    mbedtls_ssl_session_reset(&ssl);

    // 5. Wait until a client connects
    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n", ret);
        goto exit;
    }
    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // TLS 1.2 minimum
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    // 6. Handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("mbedtls_ssl_handshake returned %d\n", ret);
            goto reset;
        }
    }

    // get ALPN:
    const char *alpn_selected = mbedtls_ssl_get_alpn_protocol(&ssl);
    printf("ALPN: %s \n", alpn_selected);

    // 6. Get message from client
    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));
    ret = mbedtls_ssl_read(&ssl, buf, len);
    if (ret < 0) {
        mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
    } else {
        mbedtls_printf((char *)buf);
    }

    // 7. Send response to client
    len = sprintf((char *)buf, "Hello from Server!\n");

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf("peer closed the connection\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("mbedtls_ssl_write returned %d\n", ret);
            goto exit;
        }
    }
    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("mbedtls_ssl_close_notify returned %d\n", ret);
            goto reset;
        }
    }

    ret = 0;
    goto reset;

exit:
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret);
}