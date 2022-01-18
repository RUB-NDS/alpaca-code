#include "server.h"

char *alpn = "http/1.1";
char *servername = "tls-server.com";
char *cert = "/etc/ssl/cert-data/tls-server.com.crt";
char *key = "/etc/ssl/cert-data/tls-server.com.key";

const uint16_t port = 4433;

int malicious_alpn = 0;

int err, ret;

int main(int argc, char **argv) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:k:m")) != -1) {
        switch (opt) {
            case 'a':
                alpn = optarg;
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
            case 'm':
                malicious_alpn = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-c certfile] [-k keyfile] \n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    printf("Parameters alpn=%s servername=%s cert=%s key=%s port=%d \n", alpn, servername, cert, key, port);

    int sock;
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

    // Enable alpn callback function
    SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, NULL);

    // Enable SNI callback function
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_cb);

    // Load certificate chain and key from file
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    sock = create_socket(port);

    /* Handle connections */
    while (1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr *)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        SSL_accept(ssl);
        // err = SSL_get_error(ssl, 0);
        // printf("ERROR: %d \n", err);
        // if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        //     SSL_free(ssl);
        //     close(client);
        //     continue;
        // }

        // get message from client
        char buff[1536] = {};
        len = SSL_read(ssl, buff, sizeof(buff));
        if(len <= 0) {
            int errorvalue = SSL_get_error(ssl, len);
            if (errorvalue != SSL_ERROR_NONE) {
                printf("Errorvalue: %d return of read: %d \n", errorvalue, len);
            }

            SSL_free(ssl);
            close(client);

            continue;
        }
        printf("%s \n", buff);
        // err = SSL_get_error(ssl, 0);
        // printf("ERROR: %d \n", err);
        // if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        //     SSL_free(ssl);
        //     close(client);
        //     continue;
        // }

        // send message to client
        char *message = "Hello from Server!\n";

        len = SSL_write(ssl, message, strlen(message));
        if (len <= 0) {
            SSL_free(ssl);
            close(client);
            continue;
        }
        // err = SSL_get_error(ssl, 0);
        // printf("ERROR: %d \n", err);
        // if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        //     SSL_free(ssl);
        //     close(client);
        //     continue;
        // }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

#ifdef OPENSSL_IS_BORINGSSL
static int alpn_cb(__attribute__((unused)) SSL *ssl, const uint8_t **out, uint8_t *outlen, const uint8_t *in, unsigned inlen, __attribute__((unused)) void *arg) {
#else
static int alpn_cb(__attribute__((unused)) SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, __attribute__((unused)) void *arg) {
#endif
    // Return the alpn "invalid" in the ServerHello message, used for running Test5
    if (malicious_alpn == 1) {
        unsigned char *invalidalpn = (unsigned char *)"invalid";
        out[0] = invalidalpn;
        outlen[0] = 7;
        return SSL_TLSEXT_ERR_OK;
    }

    // Format alpn to wire-format ("http/1.1" -> "8http/1.1")
    unsigned char *alpn_formatted;
    size_t alpn_formatted_len = strlen(alpn) + 1;
    alpn_formatted = calloc(alpn_formatted_len, sizeof(unsigned char));
    alpn_formatted[0] = (unsigned char)strlen(alpn);
    for (size_t i = 1; i <= strlen(alpn); i++) {
        alpn_formatted[i] = alpn[i - 1];
    }

    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_formatted, alpn_formatted_len, in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        printf("ALPN: %s \n", *out);
        return SSL_TLSEXT_ERR_OK;
    } else {
        printf("INVALID ALPN: %s \n", *out);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

static int sni_cb(SSL *s, __attribute__((unused)) int *al, __attribute__((unused)) void *arg) {
    const char *servername_received = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

    if (servername_received != NULL) {
        if (strcasecmp(servername_received, servername) == 0) {
            printf("SNI: %s \n", servername_received);
            return SSL_TLSEXT_ERR_OK;
        } else {
            printf("INVALID SNI: %s \n", servername_received);
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    } else {
        printf("no SNI sent by client, continuing. \n");
        return SSL_TLSEXT_ERR_OK;
    }
}

int create_socket(uint16_t p) {
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(p);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}
