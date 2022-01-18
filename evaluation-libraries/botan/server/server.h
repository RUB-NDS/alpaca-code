#include <arpa/inet.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/certstor_flatfile.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <botan/x509self.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <list>

typedef int socket_type;
typedef size_t sendrecv_len_type;

socket_type make_server_socket(uint16_t port) {
    socket_type fd = ::socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        std::cerr << "Unable to acquire socket" << std::endl;
    }

    sockaddr_in socket_info;
    Botan::clear_mem(&socket_info, 1);
    socket_info.sin_family = AF_INET;
    socket_info.sin_port = htons(port);

    // FIXME: support limiting listeners
    socket_info.sin_addr.s_addr = INADDR_ANY;

    if (::bind(fd, reinterpret_cast<struct sockaddr *>(&socket_info), sizeof(struct sockaddr)) != 0) {
        ::close(fd);
        std::cerr << "server bind failed" << std::endl;
    }

    if (::listen(fd, 100) != 0) {
        ::close(fd);
        std::cerr << "listen failed" << std::endl;
    }
    return fd;
}

/* class Basic_TLS_Policy final : public Botan::TLS::Policy
{
public:
    bool require_cert_revocation_info() const override
    {
        return false;
    }
    std::vector<std::string> allowed_ciphers() const override
    {
        return {"ChaCha20Poly1305", "AES-256/GCM", "AES-128/GCM"};
    }
    std::vector<std::string> allowed_signature_hashes() const override
    {
        return {"SHA-512", "SHA-384"};
    }
    std::vector<std::string> allowed_macs() const override
    {
        return {"AEAD"};
    }
    std::vector<std::string> allowed_key_exchange_methods() const override
    {
        return {"CECPQ1", "ECDH"};
    }
    bool allow_tls10() const override { return false; }
    bool allow_tls11() const override { return false; }
    bool allow_tls12() const override { return true; }
}; */
