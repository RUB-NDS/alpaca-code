#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int create_socket(uint16_t p);

#ifdef OPENSSL_IS_BORINGSSL
static int alpn_cb(SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in, unsigned in_len, void *arg);
#else
static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *out_len, const unsigned char *in, unsigned int in_len, void *arg);
#endif

static int sni_cb(SSL *s, int *al, void *arg);
