/* This example code is placed in the public domain. */
// gnutls/gnutls/doc/examples

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* tcp.c */
void tcp_close(int sd);

/* Connects to the peer and returns a socket
 * descriptor.
 */
int tcp_connect(const char *hostname, const char *port) {
    int sockfd, portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    portno = atoi(port);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        printf("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno);
    int err = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (err < 0) {
        fprintf(stderr, "Connect error\n");
        exit(1);
    }
    return sockfd;
    /*int err, sd;
		struct sockaddr_in sa;

		struct hostent *host = gethostbyname(hostname);
        if (!host)
        {
            printf("unable to resolve : %s\n", hostname);
            return false;
        }

		//printf("%s", host->h_addr_list[0]);

		sd = socket(AF_INET, SOCK_STREAM, 0);

		memset(&sa, '\0', sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(atoi(port));
		inet_pton(AF_INET, host->h_addr_list[0], &sa.sin_addr);

		err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
		if (err < 0) {
				fprintf(stderr, "Connect error\n");
				exit(1);
		}

		return sd;*/
}

/* closes the given socket descriptor.
 */
extern void tcp_close(int sd) {
    shutdown(sd, SHUT_RDWR); /* no more receptions */
    close(sd);
}
