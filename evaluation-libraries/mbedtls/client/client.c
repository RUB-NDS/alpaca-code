/*
 *  SSL client demonstration program
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

#include <stdio.h>
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
#include "mbedtls/x509_crt.h"

int main(int argc, char** argv) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    char* host = "localhost";
    char* servername = "tls-server.com";
    char* port = "4433";
    const char* alpn[] = {"http/1.1", NULL};
    char* cert = "/etc/ssl/certs/ca.crt";

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:h:p")) != -1) {
        switch (opt) {
            case 'a':
                alpn[0] = optarg;
                break;
            case 's':
                servername = optarg;
                break;
            case 'h':
                host = optarg;
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
    printf("Parameters alpn=%s servername=%s cert=%s host=%s port=%s \n", alpn[0], servername, cert, host, port);

    unsigned char buf[1024];
    int len;
    int ret;
    uint32_t flags;

    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    mbedtls_debug_set_threshold(1);

    const char* pers = "ssl_client1";

    // 1. Initialize the RNG and the session data
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    // Minimum TLS 1.2
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers))) != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed returned %d \n", ret);
        goto cleanup;
    }

    // 2. Initialize ca certificate
    ret = mbedtls_x509_crt_parse_file(&cacert, cert);
    if (ret < 0) {
        mbedtls_printf("mbedtls_x509_crt_parse returned -0x%x\n", -ret);
        goto cleanup;
    }

    // 3. Start the connection
    if ((ret = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf("mbedtls_net_connect returned %d\n", ret);
        goto cleanup;
    }

    // 4. Setup ssl config and add ca certificate
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf("mbedtls_ssl_config_defaults returned %d\n", ret);
        goto cleanup;
    }
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // set ALPN
    if ((ret = mbedtls_ssl_conf_alpn_protocols(&conf, alpn)) != 0) {
        mbedtls_printf("mbedtls_ssl_conf_alpn_protocols returned %d\n", ret);
        goto cleanup;
    }

    // set SNI
    if ((ret = mbedtls_ssl_set_hostname(&ssl, servername)) != 0) {
        mbedtls_printf("mbedtls_ssl_set_hostname returned %d\n", ret);
        goto cleanup;
    }

    // enable Hostname verification
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf("mbedtls_ssl_setup returned %d\n", ret);
        goto cleanup;
    }

    // 5. Handshake
    // TLS 1.2 minimum
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("mbedtls_ssl_handshake returned -0x%x\n", ret);
            goto cleanup;
        }
    }

    // get ALPN:
    const char* alpn_selected = mbedtls_ssl_get_alpn_protocol(&ssl);
    printf("ALPN: %s \n", alpn_selected);

    //6. Verify the server certificate
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        char vrfy_buf[512];
        mbedtls_printf("mbedtls_ssl_get_verify_result failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);
        goto cleanup;
    }

    // 7. sent message to server
    len = sprintf((char*)buf, "Hello from Client!\n");
    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("mbedtls_ssl_write returned %d\n", ret);
            goto cleanup;
        }
        ret = 0;
    }
    // 8. get message from server
    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));
    ret = mbedtls_ssl_read(&ssl, buf, len);
    if (ret < 0) {
        mbedtls_printf("mbedtls_ssl_read returned %d\n", ret);
    } else {
        mbedtls_printf((char*)buf);
        ret = 0;
    }

    mbedtls_ssl_close_notify(&ssl);
cleanup:
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        if (strstr(error_buf, "X509 - Certificate verification failed") != NULL) {
            ret = 42;
        } else if (strstr(error_buf, "Processing of the ServerHello handshake message failed") != NULL) {
            ret = 120;
        }
        mbedtls_printf("Last error was: %d - %s\n", ret, error_buf);
        return ret;
    }
    return 0;
}