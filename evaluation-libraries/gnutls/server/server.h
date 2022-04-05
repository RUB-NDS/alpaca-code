#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(x) assert((x) >= 0)
#define LOOP_CHECK(rval, cmd) \
    do {                      \
        rval = cmd;           \
    } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

#define MAX_BUF 1024

int create_socket(u_int16_t port) {
    int listen_sd;
    struct sockaddr_in sa_serv;
    int optval = 1;
    /* Socket operations
         */
    listen_sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons(port);

    setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(int));

    bind(listen_sd, (struct sockaddr *)&sa_serv, sizeof(sa_serv));

    return listen_sd;

    printf("Server ready. Listening to port '%d'.\n\n", port);
}