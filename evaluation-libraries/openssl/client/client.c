#include "client.h"

char *alpn = "http/1.1";
char *host = "127.0.0.1";
char *port = "4433";
char *servername = "tls-server.com";
char *cert = "/etc/ssl/certs/ca.crt";

int debug = 0;

int main(int argc, char *argv[]) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:h:p:d")) != -1) {
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
            case 'd':
                debug = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-h ip] [-p port] [-c certificate] \n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    printf("Parameters alpn=%s servername=%s cert=%s host=%s port=%s \n", alpn, servername, cert, host, port);

    /* Create SSL Context */
#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
#else
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_method());
#endif
    /* Set TLS Version */
#ifdef TLS1_3_VERSION
    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        exit(2);
    }
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        exit(2);
    }
#endif

    // Format alpn to wire-format ("http/1.1" -> "8http/1.1")
    unsigned char *alpn_formatted;
    size_t alpn_formatted_len = strlen(alpn) + 1;
    alpn_formatted = calloc(alpn_formatted_len, sizeof(unsigned char));
    alpn_formatted[0] = (unsigned char)strlen(alpn);
    for (size_t i = 1; i <= strlen(alpn); i++) {
        alpn_formatted[i] = alpn[i - 1];
    }

    if (SSL_CTX_set_alpn_protos(ctx, alpn_formatted, alpn_formatted_len)) {
        fprintf(stderr, "Failed to set ALPN.\n");
        exit(3);
    }

    /* Load certificate file */
    if (!SSL_CTX_load_verify_locations(ctx, cert, NULL)) {
        fprintf(stderr, "Failed to load cert.\n");
        exit(4);
    }

    /* debug handshake */
    if (debug) {
        SSL_CTX_set_info_callback(ctx, InfoCallback);
    }

    /* Connect to server */
    char *host_with_port = calloc(sizeof(char), strlen(host) + strlen(port) + 1);
    strcat(host_with_port, host);
    strcat(host_with_port, ":");
    strcat(host_with_port, port);
    BIO *bio = BIO_new_connect(host_with_port);
    SSL *ssl = SSL_new(ctx);

/* 3. Hostname */
#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER < 0x10100000L
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!X509_VERIFY_PARAM_set1_host(param, servername, strlen(servername))) {
        fprintf(stderr, "X509_VERIFY_PARAM_set1_host\n");
        exit(5);
    }
#else
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!SSL_set1_host(ssl, servername)) {
        fprintf(stderr, "SSL_set1_host\n");
        exit(5);
    }
#endif
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    /* Set SNI */
    SSL_set_tlsext_host_name(ssl, servername);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set0_wbio(ssl, bio);
    SSL_set0_rbio(ssl, bio);
#else
    SSL_set_bio(ssl, bio, bio);
#endif

    //bio.release();
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        //int ssl_err = SSL_get_error(ssl, ret);
        //PrintSSLError(stderr, "Error while connecting", ssl_err, ret);
        int return_value = SSL_ERROR_SSL;
        ERR_print_errors_cb(&error_callback, &return_value);
        exit(return_value);
    }
    printf("Connected! \n");

    /* 1. Verify Certificate */
    X509 *ServerCert = SSL_get_peer_certificate(ssl);
    if (ServerCert) {
        X509_free(ServerCert);
    } else {
        fprintf(stderr, "SSL_get_peer_certificate.\n");
        exit(7);
    }

    /* 2. Verify Certificate Chain  */
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Error in SSL_get_verify_result.\n");
        exit(8);
    }

    // strict ALPN verification
    const unsigned char *alpn_received;
    unsigned int alpn_received_len;
    SSL_get0_alpn_selected(ssl, &alpn_received, &alpn_received_len);

    if (alpn_received_len > 0) {
        if (strncmp((const char *)alpn_received, alpn, alpn_received_len) == 0) {
            printf("ALPN: %.*s \n", alpn_received_len, alpn_received);
        } else {
            fprintf(stderr, "INVALID ALPN: %.*s \n", alpn_received_len, alpn_received);
            return TLS1_AD_NO_APPLICATION_PROTOCOL;
        }
    } else {
        printf("No ALPN negotiated ! %.*s\n", alpn_received_len, alpn_received);
        //exit(10);
    }

    /* send message to server */
    char *message = "Hello from Client!\n";
    SSL_write(ssl, message, strlen(message));

    /* get message from server */
    char buff[1536] = {};
    SSL_read(ssl, buff, sizeof(buff));
    printf("%s", buff);

    /* Close connection */
    BIO_free(bio);
    SSL_CTX_free(ctx);

    return 0;
}

/* Debug info callback for handshake */
static void InfoCallback(const SSL *ssl, int type, __attribute__((unused)) int value) {
    switch (type) {
        case SSL_CB_HANDSHAKE_START:
            printf("Handshake started\n");
            break;
        case SSL_CB_HANDSHAKE_DONE:
            printf("Handshake done\n");
            break;
        case SSL_CB_CONNECT_LOOP:
            printf("Handshake progress: %s\n", SSL_state_string_long(ssl));
            break;
    }
}

static int error_callback(const char *str, size_t len, void *err) {
    if (strstr(str, "SSL alert number 120") != NULL || strstr(str, "INVALID_ALPN_PROTOCOL") != NULL) {
        printf("TLSV1_ALERT_NO_APPLICATION_PROTOCOL \n");
        //err = 1;
        (*(int *)err) = TLS1_AD_NO_APPLICATION_PROTOCOL;
    } else if (strstr(str, "CERTIFICATE_VERIFY_FAILED") != NULL || strstr(str, "certificate verify failed") != NULL) {
        printf("CERTIFICATE_VERIFY_FAILED \n");
        //err = 1;
        (*(int *)err) = SSL3_AD_BAD_CERTIFICATE;
    } else if (strstr(str, "TLSV1_ALERT_UNRECOGNIZED_NAME") != NULL || strstr(str, "tlsv1 unrecognized name") != NULL) {
        printf("TLSV1_ALERT_UNRECOGNIZED_NAME \n");
        //err = 1;
        (*(int *)err) = TLS1_AD_UNRECOGNIZED_NAME;
    } else {
        printf("%s", str);
        (*(int *)err) = SSL_ERROR_SSL;
    }
    return 0;
}

void PrintSSLError(FILE *file, const char *msg, int ssl_err, int ret) {
    switch (ssl_err) {
        case SSL_ERROR_SSL:
            fprintf(stderr, " %s \n", ERR_reason_error_string(ERR_peek_error()));
            break;
        case SSL_ERROR_SYSCALL:
            if (ret == 0) {
                fprintf(stderr, " peer closed connection \n");
            } else {
                char *error = strerror(errno);
                fprintf(stderr, " %s %s \n", msg, error);
            }
            break;
        case SSL_ERROR_ZERO_RETURN:
            fprintf(stderr, "received close_notify \n");
            break;
        default:
            break;
#ifdef OPENSSL_IS_BORINGSSL
            fprintf(file, "%s: unexpected error: %s\n", msg, SSL_error_description(ssl_err));
#else
            fprintf(file, "%s: unexpected error: %s\n", msg, ERR_reason_error_string(ssl_err));
#endif
    }
    //ERR_print_errors_fp(file);
    int err = 5;
    ERR_print_errors_cb(&error_callback, &err);
}