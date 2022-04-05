/* 
This example code is placed in the public domain. 
gnutls/gnutls/doc/examples/ex-serv-x509.c
*/

#include "server.h"

u_int16_t port = 4433;
const char *servername = "tls-server.com";
const char *cert = "/etc/ssl/cert-data/tls-server.com-chain.crt";
const char *key = "/etc/ssl/cert-data/tls-server.com.key";
gnutls_datum_t alpn = {.data = (unsigned char *)"http/1.1", .size = 8U};

#define MSG "Hello from Server!"

static int ext_hook_func(void *ctx, unsigned tls_id,
                         const unsigned char *data, unsigned size) {
    if (tls_id == 0) { /* 0 = server_name extension */
        const unsigned char *servername_received = data + 5;

        if (strcmp(servername, servername_received) != 0) {
            fprintf(stderr, "INVALID SNI: %s\n", servername_received);
            return GNUTLS_E_UNRECOGNIZED_NAME;
        }
        else {
            printf("SNI: %s\n", servername_received);
        }
    }
    return 0;
}

static int handshake_hook_func(gnutls_session_t session, unsigned int htype,
                    unsigned when, unsigned int incoming, const gnutls_datum_t *msg) {
    // call hook for parsing the raw TLS extension
    return gnutls_ext_raw_parse(NULL, ext_hook_func, msg, GNUTLS_EXT_RAW_FLAG_TLS_CLIENT_HELLO);
}

int main(int argc, char **argv) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:k:")) != -1) {
        switch (opt) {
            case 'a':
                alpn.data = (unsigned char *)optarg;
                alpn.size = strlen(optarg);
                break;
            case 's':
                servername = optarg;
                break;
            case 'c':
                cert = optarg;
                break;
            case 'k':
                key = optarg;
                break;
            /*case 'p':
			port = optarg;
			break;*/
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-c certfile] [-k keyfile] \n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    printf("Parameters alpn=%s servername=%s cert=%s key=%s port=%d \n", alpn.data, servername, cert, key, port);

    int sd, ret;
    gnutls_certificate_credentials_t x509_cred;
    gnutls_priority_t priority_cache;
    struct sockaddr_in sa_cli;
    socklen_t client_len;
    gnutls_session_t session;
    char buffer[MAX_BUF + 1];

    // Initialize gnutls
    CHECK(gnutls_global_init());
    CHECK(gnutls_certificate_allocate_credentials(&x509_cred));

    // Load certificate and key file
    CHECK(gnutls_certificate_set_x509_key_file(x509_cred, cert, key, GNUTLS_X509_FMT_PEM));

    CHECK(gnutls_priority_init(&priority_cache, NULL, NULL));
    gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_MEDIUM);

    // Create socket and listen on port
    int listen_sd = create_socket(port);
    listen(listen_sd, 1024);
    client_len = sizeof(sa_cli);
    for (;;) {
        CHECK(gnutls_init(&session, GNUTLS_SERVER));
        CHECK(gnutls_priority_set(session, priority_cache));
        CHECK(gnutls_priority_set_direct(session, "NORMAL:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:+VERS-TLS1.2", 0));
        CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));

        // Set ALPN
        CHECK(gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY));

        gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO, GNUTLS_HOOK_PRE, handshake_hook_func);

        /* We don't request any certificate from the client.
        * If we did we would need to verify it. One way of
        * doing that is shown in the "Verifying a certificate"
        * example.
        */
        gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);
        gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        sd = accept(listen_sd, (struct sockaddr *)&sa_cli, &client_len);

        gnutls_transport_set_int(session, sd);

        // Handshake
        LOOP_CHECK(ret, gnutls_handshake(session));
        if (ret < 0) {
            if (ret == GNUTLS_E_NO_APPLICATION_PROTOCOL) {
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_NO_APPLICATION_PROTOCOL);
            } else if (ret == GNUTLS_E_UNRECOGNIZED_NAME) {
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_UNRECOGNIZED_NAME);
            }

            close(sd);
            gnutls_deinit(session);
            fprintf(stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror(ret));
            continue;
        }

        //for (;;) {
        // Receive message from client
        LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));

        if (ret == 0) {
            printf("\n- Peer has closed the GnuTLS connection\n");
            //break;
        } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
            fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
        } else if (ret < 0) {
            fprintf(stderr,
                    "\n*** Received corrupted "
                    "data(%d). Closing the connection.\n\n",
                    ret);
            //break;
        } else if (ret > 0) {
            printf("%.*s", ret, buffer);

            // Send message to client
            CHECK(gnutls_record_send(session, MSG, strlen(MSG)));
            LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));
        }
        //}
        printf("\n");
        /* do not wait for the peer to close the connection. */
        //gnutls_bye(session, GNUTLS_SHUT_WR);

        close(sd);
        gnutls_deinit(session);
    }
    close(listen_sd);

    gnutls_certificate_free_credentials(x509_cred);
    gnutls_priority_deinit(priority_cache);

    gnutls_global_deinit();

    return 0;
}
