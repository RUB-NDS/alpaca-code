/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "examples.h"
#include "tcp.c"

/* A very basic TLS client, with X.509 authentication and server certificate
 * verification. Note that error recovery is minimal for simplicity.
 */

#define CHECK(x) assert((x) >= 0)
#define LOOP_CHECK(rval, cmd)                                         \
    do {                                                              \
        rval = cmd;                                                   \
    } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED); \
    assert(rval >= 0)

#define MAX_BUF 1024
#define MSG "Hello from Client!"

const char *host = "localhost";
const char *port = "4433";
const char *servername = "tls-server.com";
const char *cert = "/etc/ssl/certs/ca.crt";
gnutls_datum_t alpn = {.data = (unsigned char *)"http/1.1", .size = 8U};

int main(int argc, char *argv[]) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:h:p")) != -1) {
        switch (opt) {
            case 'a':
                alpn.data = (unsigned char *)optarg;
                alpn.size = strlen(optarg);
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
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-h ip] [-p port] [-c certificate] \n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    //std::cout << "Parameters alpn=" << alpn.data << " servername=" << servername << " cert=" << cert << " host=" << host << std::endl;
    printf("Parameters alpn=%s servername=%s cert=%s host=%s port=%s \n", alpn.data, servername, cert, host, port);

    int ret, socket, ii;
    gnutls_session_t session;
    char buffer[MAX_BUF + 1], *desc;
    gnutls_datum_t out;
    gnutls_certificate_type_t type;
    unsigned status;
    gnutls_certificate_credentials_t xcred;

    if (gnutls_check_version("3.4.6") == NULL) {
        fprintf(stderr, "GnuTLS 3.4.6 or later is required for this example\n");
        exit(1);
    }

    /* for backwards compatibility with gnutls < 3.3.0 */
    CHECK(gnutls_global_init());

    /* X509 stuff */
    CHECK(gnutls_certificate_allocate_credentials(&xcred));
    CHECK(gnutls_certificate_set_x509_trust_file(xcred, cert, GNUTLS_X509_FMT_PEM));

    /* sets the system trusted CAs for Internet PKI */
    //CHECK(gnutls_certificate_set_x509_system_trust(xcred));

    /* If client holds a certificate it can be set using the following:
    *
    gnutls_certificate_set_x509_key_file (xcred, "cert.pem", "key.pem", 
    GNUTLS_X509_FMT_PEM); 
    */

    /* Initialize TLS session */
    CHECK(gnutls_init(&session, GNUTLS_CLIENT));

    // Set SNI
    CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, servername, strlen(servername)));

    // Set strict ALPN
    CHECK(gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY));

    /* It is recommended to use the default priorities */
    CHECK(gnutls_set_default_priority(session));

    /* put the x509 credentials to the current session */
    CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred));

    // hostname verification
    gnutls_session_set_verify_cert(session, servername, 0);

    // connect to the peer
    socket = tcp_connect(host, port);

    gnutls_transport_set_int(session, socket);
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    // do the handshake
    do {
        ret = gnutls_handshake(session);
    } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
    if (ret < 0) {
        if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
            /* check certificate verification status */
            type = gnutls_certificate_type_get(session);
            status = gnutls_session_get_verify_cert_status(session);
            CHECK(gnutls_certificate_verification_status_print(status, type, &out, 0));
            printf("cert verify output: %s\n", out.data);
            gnutls_free(out.data);
        }
        fprintf(stderr, "*** Handshake failed: %s\n", gnutls_strerror(ret));
        goto end;
    } else {
        desc = gnutls_session_get_desc(session);
        //printf("- Session info: %s\n", desc);
        gnutls_free(desc);
    }

    // Send message to server
    LOOP_CHECK(ret, gnutls_record_send(session, MSG, strlen(MSG)));

    // Receive message from server
    LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));
    if (ret == 0) {
        printf("- Peer has closed the TLS connection\n");
        goto end;
    } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
        fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
    } else if (ret < 0) {
        fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
        goto end;
    }

    if (ret > 0) {
        //printf("- Received %d bytes: ", ret);
        //std::cout << ret << std::endl;
        for (ii = 0; ii < ret; ii++) {
            fputc(buffer[ii], stdout);
        }
        fputs("\n", stdout);
        ret = 0;
    }

    CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));

end:

    tcp_close(socket);

    gnutls_deinit(session);

    gnutls_certificate_free_credentials(xcred);

    gnutls_global_deinit();

    return ret;
}
