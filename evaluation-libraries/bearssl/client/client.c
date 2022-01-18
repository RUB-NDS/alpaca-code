#include "client.h"

int main(int argc, char *argv[]) {
    // Disable buffering on stdout so docker output is shown
    setbuf(stdout, NULL);

    const char *host = "127.0.0.1";
    const char *alpn = "http/1.1";
    const char *servername = "tls-server.com";
    const char *port = "4433";

    int opt;
    while ((opt = getopt(argc, argv, "a:s:h:p:")) != -1) {
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
            /*case 'c':
			cert = optarg;
			break;*/
            case 'p':
                port = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-h ip] [-p port]  \n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    printf("Parameters alpn=%s servername=%s cert=ca.crt host=%s \n", alpn, servername, host);

    int err;
    int fd;
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context ioc;

    /*
	 * Open the socket to the target server.
	 */
    fd = host_connect(host, port);
    if (fd < 0) {
        return EXIT_FAILURE;
    }

    /*
	 * Initialise the client context:
	 * -- Use the "full" profile (all supported algorithms).
	 * -- The provided X.509 validation engine is initialised, with
	 *    the hardcoded trust anchor.
	 */
    br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);

    /*
	 * Set the I/O buffer to the provided array. We allocated a
	 * buffer large enough for full-duplex behaviour with all
	 * allowed sizes of SSL records, hence we set the last argument
	 * to 1 (which means "split the buffer into separate input and
	 * output areas").
	 */
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

    /* Set TLS 1.2 */
    br_ssl_engine_set_versions(&sc.eng, BR_TLS12, BR_TLS12);

    /* set ALPN */
    const char **alpn_ptr;
    alpn_ptr = malloc(sizeof(char) * strlen(alpn));
    alpn_ptr[0] = alpn;
    br_ssl_engine_set_protocol_names(&sc.eng, alpn_ptr, 1);
    br_ssl_engine_add_flags(&sc.eng, BR_OPT_FAIL_ON_ALPN_MISMATCH);

    /*
	 * Reset the client context, for a new handshake. We provide the
	 * target host name: it will be used for the SNI extension. The
	 * last parameter is 0: we are not trying to resume a session.
	 */
    br_ssl_client_reset(&sc, servername, 0);

    /*
	 * Initialise the simplified I/O wrapper context, to use our
	 * SSL client context, and the two callbacks for socket I/O.
	 */
    br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);
    br_sslio_flush(&ioc);

    const char *alpn_received = br_ssl_engine_get_selected_protocol(&sc.eng);
    printf("ALPN negotiatiated: %s\n", alpn_received);

    // send message to server
    //const char *message = "Hello from Client!";
    //br_sslio_write(&ioc, message, strlen(message));

    for (;;) {
        // send message to server
        const char *message = "Hello from Client!";
        br_sslio_write(&ioc, message, strlen(message));
        br_sslio_flush(&ioc);

        // get message from server
        unsigned char tmp[512];
        int rlen = br_sslio_read(&ioc, tmp, sizeof tmp);
        if (rlen < 0) {
            break;
        }
        if (rlen > 0) {
            printf("%s \n", tmp);
            break;
        }
    }
    // Close the SSL connection
    br_sslio_close(&ioc);
    /*
	 * Close the socket.
	 */
    close(fd);

    /*
	 * Check whether we closed properly or not. If the engine is
	 * closed, then its error status allows to distinguish between
	 * a normal closure and a SSL error.
	 *
	 * If the engine is NOT closed, then this means that the
	 * underlying network socket was closed or failed in some way.
	 * Note that many Web servers out there do not properly close
	 * their SSL connections (they don't send a close_notify alert),
	 * which will be reported here as "socket closed without proper
	 * SSL termination".
	 */
    if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
        err = br_ssl_engine_last_error(&sc.eng);
        if (err == 0) {
            fprintf(stderr, "SSL closed.\n");
            return EXIT_SUCCESS;
        } else if (err == BR_ERR_X509_BAD_SERVER_NAME) {
            fprintf(stderr, "ERROR BR_ERR_X509_BAD_SERVER_NAME\n");
            return 112;
        } else if (err == BR_ALERT_BAD_CERTIFICATE) {
            fprintf(stderr, "ERROR BR_ALERT_BAD_CERTIFICATE\n");
        } else if (err == BR_ALERT_CERTIFICATE_UNKNOWN) {
            fprintf(stderr, "ERROR BR_ALERT_CERTIFICATE_UNKNOWN\n");
        } else if (err == BR_ALERT_NO_APPLICATION_PROTOCOL) {
            fprintf(stderr, "ERROR BR_ALERT_NO_APPLICATION_PROTOCOL\n");
            return 120;
        } else if (err == BR_OPT_FAIL_ON_ALPN_MISMATCH) {
            fprintf(stderr, "ERROR BR_OPT_FAIL_ON_ALPN_MISMATCH\n");
            return 120;
        } else if (err == BR_ERR_BAD_SNI) {
            fprintf(stderr, "ERROR BR_ERR_BAD_SNI\n");
        } else {
            fprintf(stderr, "SSL ERROR %d\n", err);
        }
        return err;
    } else {
        fprintf(stderr, "SSL socket closed without proper termination\n");
        return EXIT_FAILURE;
    }
}