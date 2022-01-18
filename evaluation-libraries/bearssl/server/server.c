#include "server.h"

#define CHECK(x) x;

const char *servername = "tls-server.com";

int main(int argc, char *argv[]) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    const char *alpn = "http/1.1";
    const char *port = "4433";
    int wrong_certificate = 0;
    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:w")) != -1) {
        switch (opt) {
            case 'a':
                alpn = optarg;
                break;
            case 's':
                servername = optarg;
                break;
            case 'w':
                wrong_certificate = 1;
                break;
            /*case 'k':
			key = optarg;
			break;*/
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-w uses wrong cert] \n", argv[0]);
                return EXIT_FAILURE;
        }
    }
    printf("Parameters alpn=%s servername=%s use_wrong_cert=%d ", alpn, servername, wrong_certificate);

    int fd;

    const char **alpn_ptr;
    alpn_ptr = malloc(sizeof(char) * strlen(alpn));
    alpn_ptr[0] = alpn;

    unsigned char tmp[512];
    const char *message = "Hello from Server!";

    int cfd;
    br_ssl_server_context sc;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context ioc;
    int err;

    /*
	 * Open the server socket.
	 */
    fd = host_bind(NULL, port);
    if (fd < 0) {
        return EXIT_FAILURE;
    }

    /*
	 * Process each client, one at a time.
	 */
    for (;;) {
        cfd = accept_client(fd);
        if (cfd < 0) {
            return EXIT_FAILURE;
        }

        /*
         * Choose certificate
         * CHAIN=tls-server.com-chain.crt
         * WRONG_CHAIN=wrong-cn.com-chain.crt
         */
        if (wrong_certificate == 1) {
            br_ssl_server_init_full_rsa(&sc, WRONG_CHAIN, WRONG_CHAIN_LEN, &WRONG_RSA);
        } else {
            br_ssl_server_init_full_rsa(&sc, CHAIN, CHAIN_LEN, &RSA);
        }

        /* from bearssl-0.6/src/ssl/br_ssl_server_set_single_rsa.c
            normally gets called by br_ssl_server_init_full_rsa that then calls br_ssl_server_set_single_rsa

            change policy handler to a custom one

            sr_choose overrides the method that processes the ClientHello and chooses certificates, cipher suited etc.
        */
        static const br_ssl_server_policy_class sr_policy_vtable = {
            sizeof(br_ssl_server_policy_rsa_context),
            choose,
            do_keyx,
            do_sign};
        (&sc)->chain_handler.single_rsa.vtable = &sr_policy_vtable;
        (&sc)->policy_vtable = &(&sc)->chain_handler.single_rsa.vtable;

        /* Set TLS 1.2 */
        br_ssl_engine_set_versions(&sc.eng, BR_TLS12, BR_TLS12);

        /*
         * Set the I/O buffer to the provided array. We
         * allocated a buffer large enough for full-duplex
         * behaviour with all allowed sizes of SSL records,
         * hence we set the last argument to 1 (which means
         * "split the buffer into separate input and output
         * areas").
         */
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

        /* set ALPN */

        br_ssl_engine_set_protocol_names(&sc.eng, alpn_ptr, 1);

        // Enable strict ALPN
        br_ssl_engine_add_flags(&sc.eng, BR_OPT_FAIL_ON_ALPN_MISMATCH);

        /*
         * Reset the server context, for a new handshake.
         */
        br_ssl_server_reset(&sc);

        /*
         * Initialise the simplified I/O wrapper context.
         */
        br_sslio_init(&ioc, &sc.eng, sock_read, &cfd, sock_write, &cfd);
        br_sslio_flush(&ioc);

        for (;;) {
            // get message from client
            int rlen = br_sslio_read(&ioc, tmp, sizeof tmp);
            if (rlen < 0) {
                break;
            } else {
                printf("%s \n", tmp);
                // send message to server
                br_sslio_write(&ioc, message, strlen(message));
                br_sslio_close(&ioc);
                break;
            }
        }

        // Check if SSL closed correctly
        err = br_ssl_engine_last_error(&sc.eng);
        if (err == 0) {
            fprintf(stderr, "SSL closed.\n");
        } else if (err == BR_ERR_X509_BAD_SERVER_NAME) {
            fprintf(stderr, "ERROR BR_ERR_X509_BAD_SERVER_NAME\n");
        } else if (err == BR_ERR_IO) {
            fprintf(stderr, "BR_ERR_IO\n");
        } else if (err == BR_ALERT_BAD_CERTIFICATE) {
            fprintf(stderr, "ERROR BR_ALERT_BAD_CERTIFICATE\n");
        } else if (err == BR_ALERT_CERTIFICATE_UNKNOWN) {
            fprintf(stderr, "ERROR BR_ALERT_CERTIFICATE_UNKNOWN\n");
        } else if (err == BR_ALERT_NO_APPLICATION_PROTOCOL) {
            fprintf(stderr, "ERROR BR_ALERT_NO_APPLICATION_PROTOCOL\n");
        } else if (err == BR_OPT_FAIL_ON_ALPN_MISMATCH) {
            fprintf(stderr, "ERROR BR_OPT_FAIL_ON_ALPN_MISMATCH\n");
        } else if (err == BR_ERR_BAD_SNI) {
            fprintf(stderr, "ERROR BR_ERR_BAD_SNI\n");
        } else {
            fprintf(stderr, "SSL ERROR %d\n", err);
        }
        close(cfd);
    }
}