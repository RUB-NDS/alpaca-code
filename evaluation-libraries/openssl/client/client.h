#include <errno.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <unistd.h>

void PrintSSLError(FILE *file, const char *msg, int ssl_err, int ret);

static void InfoCallback(const SSL *ssl, int type, int value);

static int error_callback(const char *str, size_t len, void *err);