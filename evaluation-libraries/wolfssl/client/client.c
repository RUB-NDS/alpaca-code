/* client-tls.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "client.h"

//#define HAVE_ALPN
//#define HAVE_SNI

int main(int argc, char **argv) {
    char *host = "localhost";
    char *servername = "tls-server.com";
    char *port = "4433";
    char *alpn = "http/1.1";
    char *cert = "/etc/ssl/certs/ca.crt";

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:h:p")) != -1) {
        switch (opt) {
            case 'a':
                alpn = optarg;
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
    printf("Parameters alpn=%s servername=%s cert=%s host=%s port=%s \n", alpn, servername, cert, host, port);

    int sockfd;
    char buff[256];
    int len;
    int ret;

    /* declare wolfSSL objects */
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    sockfd = tcp_connect(host, port);

    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto socket_cleanup;
    }

    /* Load client certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, cert, NULL)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                cert);
        goto ctx_cleanup;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        goto ctx_cleanup;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }

    /* set ALPN */
    if (wolfSSL_UseALPN(ssl, alpn, sizeof(alpn), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to set ALPN \n");
        goto cleanup;
    }

    /* set SNI */
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, servername, strlen(servername));
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to set SNI \n");
        goto cleanup;
    }

    /* hostname verification */
    ret = wolfSSL_check_domain_name(ssl, servername);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: setting hostname verification \n");
        goto cleanup;
    }

    /* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        int err = wolfSSL_get_error(ssl, ret);
        char *error_string = wolfSSL_ERR_error_string(err, buffer);
        fprintf(stderr, "wolfSSL_connect error = %s\n", error_string);
        if (strstr(error_string, "Unrecognized protocol name Error") != NULL) {
            ret = 120;
        }
        if (strstr(error_string, "peer subject name mismatch") != NULL) {
            ret = 42;
        }
        goto cleanup;
    }

    /* Send message to server */
    char *message = "Hello from Client!\n";
    strcpy(buff, message);
    len = strlen(message);
    if ((ret = wolfSSL_write(ssl, buff, len)) != len) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int)len);
        goto cleanup;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto cleanup;
    }
    printf("%s\n", buff);

    /* Bidirectional shutdown */
    while (wolfSSL_shutdown(ssl) == SSL_SHUTDOWN_NOT_DONE) {
        //printf("Shutdown not complete\n");
    }

    printf("Connection closed.\n");

    ret = 0;

    /* Cleanup and return */
cleanup:
    wolfSSL_free(ssl); /* Free the wolfSSL object                  */
ctx_cleanup:
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(sockfd); /* Close the connection to the server       */
    return ret;    /* Return reporting a success               */
}