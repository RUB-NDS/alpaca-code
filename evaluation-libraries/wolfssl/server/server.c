/* server-tls.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(int argc, char **argv) {
    char *servername = "tls-server.com";
    uint16_t port = 4433;
    char *alpn = "http/1.1";
    char *cert = "/etc/ssl/cert-data/tls-server.com-chain.crt";
    char *key = "/etc/ssl/cert-data/tls-server.com.key";

    int sockfd = SOCKET_INVALID;
    int connd = SOCKET_INVALID;
    struct sockaddr_in clientAddr;
    socklen_t size = sizeof(clientAddr);
    char buff[256];
    int len;
    int ret;
    const char *reply = "Hello from Server!\n";

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:k:p")) != -1) {
        switch (opt) {
            case 'a':
                alpn = optarg;
                break;
            case 's':
                servername = optarg;
                break;
            case 'k':
                key = optarg;
                break;
            case 'p':
                port = strtol(optarg, NULL, 10);
                break;
            case 'c':
                cert = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-k keyfile] [-p port] [-c certificate] \n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    printf("Parameters alpn=%s servername=%s cert=%s key=%s port=%d \n", alpn, servername, cert, key, port);

    /* declare wolfSSL objects */
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto exit;
    }

    /* Load server certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_chain_file(ctx, cert)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", cert);
        goto exit;
    }

    /* Load server key into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", key);
        goto exit;
    }

    /* set SNI */
    ret = wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, servername, strlen(servername));
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to set SNI \n");
        goto exit;
    }

    sockfd = create_socket(port);
    listen(sockfd, 1024);

    for (;;) {
        fprintf(stderr, "Waiting for a connection...\n");

        /* Accept client connections */
        if ((connd = accept(sockfd, (struct sockaddr *)&clientAddr, &size)) == -1) {
            fprintf(stderr, "ERROR: failed to accept the connection\n");
            continue;
        }

        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            continue;
        }

        /* set ALPN */
        if (wolfSSL_UseALPN(ssl, alpn, sizeof(alpn), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to set ALPN \n");
            wolfSSL_shutdown(ssl);
            continue;
        }

        /* Attach wolfSSL to the socket */
        wolfSSL_set_fd(ssl, connd);

        /* Establish TLS connection */
        ret = wolfSSL_accept(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            char buffer[WOLFSSL_MAX_ERROR_SZ];
            fprintf(stderr, "wolfSSL_accept error = %s\n", wolfSSL_ERR_error_string(wolfSSL_get_error(ssl, ret), buffer));
            wolfSSL_shutdown(ssl);
            continue;
        }

        //fprintf(stderr, "Client connected successfully \n");

        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));
        if ((ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1) {
            fprintf(stderr, "ERROR: failed to read\n");
            wolfSSL_shutdown(ssl);
            continue;
        }

        /* Print to stdout any data the client sends */
        fprintf(stderr, "%s\n", buff);

        /* Check for server shutdown command */
        if (strncmp(buff, "shutdown", 8) == 0) {
            printf("Shutdown command issued!\n");
            wolfSSL_shutdown(ssl);
            continue;
        }

        /* Write our reply into buff */
        memset(buff, 0, sizeof(buff));
        memcpy(buff, reply, strlen(reply));
        len = strnlen(buff, sizeof(buff));

        /* Reply back to the client */
        if ((ret = wolfSSL_write(ssl, buff, len)) != len) {
            fprintf(stderr, "ERROR: failed to write\n");
            wolfSSL_shutdown(ssl);
            continue;
        }

        /* Notify the client that the connection is ending */
        wolfSSL_shutdown(ssl);
        fprintf(stderr, "Connection closed.\n");

        /* Cleanup after this connection */
        wolfSSL_free(ssl); /* Free the wolfSSL object              */
        close(connd);      /* Close the connection to the client   */
    }

    ret = 0;
exit:
    /* Cleanup and return */
    if (ssl)
        wolfSSL_free(ssl); /* Free the wolfSSL object              */
    if (connd != SOCKET_INVALID)
        close(connd); /* Close the connection to the client   */
    if (sockfd != SOCKET_INVALID)
        close(sockfd); /* Close the socket listening for clients   */
    if (ctx)
        wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();         /* Cleanup the wolfSSL environment          */

    return ret; /* Return reporting a success               */
}