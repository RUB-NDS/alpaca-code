#include <arpa/inet.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/certstor_flatfile.h>
#include <botan/certstor_system.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager.h>
#include <botan/x509cert.h>
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

socket_type m_sockfd;
std::string host = "127.0.0.1";
std::string cert = "/etc/ssl/certs";
std::string servername = "tls-server.com";
std::vector<std::string> alpn = {"http/1.1"};
uint16_t port = 4433;

bool message_received = false;

socket_type connect_to_host(const std::string &host, uint16_t port, bool tcp) {
    addrinfo hints;
    Botan::clear_mem(&hints, 1);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;
    addrinfo *res, *rp = nullptr;

    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        std::cerr << "getaddrinfo failed for" << host << std::endl;
    }

    socket_type fd = 0;

    for (rp = res; rp != nullptr; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (fd == -1) {
            continue;
        }

        if (::connect(fd, rp->ai_addr, static_cast<socklen_t>(rp->ai_addrlen)) != 0) {
            ::close(fd);
            continue;
        }

        break;
    }

    ::freeaddrinfo(res);

    if (rp == nullptr)  // no address succeeded
    {
        std::cerr << "connect failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    return fd;
}

class Basic_TLS_Policy final : public Botan::TLS::Policy {
   public:
    bool require_cert_revocation_info() const override {
        return false;
    }
    bool acceptable_protocol_version(Botan::TLS::Protocol_Version version) const override {
        if (version == Botan::TLS::Protocol_Version::TLS_V12 && allow_tls12())
            return true;
        return false;
    }
};

class Basic_Credentials_Manager : public Botan::Credentials_Manager {
   public:
    Basic_Credentials_Manager(const std::string &ca_path) {
        if (ca_path.empty() == false) {
            m_certstores.push_back(std::make_shared<Botan::Certificate_Store_In_Memory>(ca_path));
        }
    }

    Basic_Credentials_Manager() {
        m_certstores.push_back(std::make_shared<Botan::System_Certificate_Store>());
    }

    Basic_Credentials_Manager(const std::string &server_crt, const std::string &server_key) {
        Certificate_Info cert;

        Botan::DataSource_Stream key_in(server_key);
        cert.key = Botan::PKCS8::load_key(key_in);

        Botan::DataSource_Stream in(server_crt);
        while (!in.end_of_data()) {
            try {
                cert.certs.push_back(Botan::X509_Certificate(in));
            } catch (std::exception &) {
            }
        }
        m_creds.push_back(cert);
    }

    std::vector<Botan::Certificate_Store *>
    trusted_certificate_authorities(const std::string &type,
                                    const std::string & /*hostname*/) override {
        std::vector<Botan::Certificate_Store *> v;

        // don't ask for client certs
        if (type == "tls-server.com") {
            return v;
        }

        for (auto const &cs : m_certstores) {
            v.push_back(cs.get());
        }

        return v;
    }

    std::vector<Botan::X509_Certificate> cert_chain(
        const std::vector<std::string> &algos,
        const std::string &type,
        const std::string &hostname) override {
        BOTAN_UNUSED(type);

        for (auto const &i : m_creds) {
            if (std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end()) {
                continue;
            }

            if (hostname != "" && !i.certs[0].matches_dns_name(hostname)) {
                continue;
            }

            return i.certs;
        }

        return std::vector<Botan::X509_Certificate>();
    }

    Botan::Private_Key *private_key_for(const Botan::X509_Certificate &cert,
                                        const std::string & /*type*/,
                                        const std::string & /*context*/) override {
        for (auto const &i : m_creds) {
            if (cert == i.certs[0]) {
                return i.key.get();
            }
        }

        return nullptr;
    }

   public:
    struct Certificate_Info {
        std::vector<Botan::X509_Certificate> certs;
        std::shared_ptr<Botan::Private_Key> key;
    };

    std::vector<Certificate_Info> m_creds;
    std::vector<std::shared_ptr<Botan::Certificate_Store>> m_certstores;
};

/**
 * @brief Callbacks invoked by TLS::Channel.
 *
 * Botan::TLS::Callbacks is an abstract class.
 * For improved readability, only the functions that are mandatory
 * to implement are listed here. See src/lib/tls/tls_callbacks.h.
 */
class Callbacks : public Botan::TLS::Callbacks {
   public:
    void tls_emit_data(const uint8_t buf[], size_t length) override {
        size_t offset = 0;

        while (length) {
            ssize_t sent = ::send(m_sockfd, buf + offset, length, MSG_NOSIGNAL);

            if (sent == -1) {
                if (errno == EINTR) {
                    sent = 0;
                } else {
                    std::cerr << "Socket write failed errno=" << std::to_string(errno) << std::endl;
                    exit(EXIT_FAILURE);
                }
            }

            offset += sent;
            length -= sent;
        }
    }
    void tls_record_received(uint64_t /*seq_no*/, const uint8_t input[], size_t input_len) override {
        for (size_t i = 0; i != input_len; ++i) {
            std::cout << input[i];
        }
        std::cout << std::endl;
        message_received = true;
    }

    void tls_alert(Botan::TLS::Alert alert) override {
        std::cerr << "Alert: " << alert.type_string() << "\n";
        if (alert.is_fatal()) {
            exit(alert.type());
        }
    }

    bool tls_session_established(const Botan::TLS::Session &session) override {
        return true;
    }
};

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:h:d")) != -1) {
        switch (opt) {
            case 'a':
                alpn[0] = optarg;
                break;
            case 's':
                servername = optarg;
                break;
            case 'h':
                host = optarg;
                break;
            case 'c':
                cert = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-c CAfolder] [-h ip] \n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    std::cout << "Parameters alpn=" << alpn[0] << " servername=" << servername << " cert=" << cert << std::endl;

    struct sockaddr_storage addrbuf;
    m_sockfd = -1;
    std::string hostname;
    if (!host.empty() &&
        inet_pton(AF_INET, host.c_str(), &addrbuf) != 1 &&
        inet_pton(AF_INET6, host.c_str(), &addrbuf) != 1) {
        hostname = host;
    }

    m_sockfd = connect_to_host(host, port, true);

    Basic_Credentials_Manager creds(cert);
    Basic_TLS_Policy policy;
    Callbacks callbacks;
    Botan::AutoSeeded_RNG rng;
    Botan::TLS::Session_Manager_In_Memory session_mgr(rng);

    // open the tls connection
    Botan::TLS::Client client(callbacks,
                              session_mgr,
                              creds,
                              policy,
                              rng,
                              Botan::TLS::Server_Information(servername, port),
                              Botan::TLS::Protocol_Version::TLS_V12, alpn);

    bool first_active = true;

    while (!client.is_closed()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_sockfd, &readfds);

        // Send Application Data
        if (client.is_active() && first_active) {
            if (!alpn.empty()) {
                std::string app = client.application_protocol();
                if (app.compare(alpn[0]) != 0) {
                    std::cout << "INVALID ALPN: " << client.application_protocol() << "\n";
                    exit(120);
                }
                std::cout << "ALPN: " << client.application_protocol() << "\n";
            }

            /* Send Message to Server */
            std::string message = "Hello from Client!\n";
            std::vector<uint8_t> myVector(message.begin(), message.end());
            client.send(myVector.data(), message.size());

            first_active = false;
            //client.close();
            //break;
        }
        if (client.is_active() && message_received) {
            client.close();
        }
        if (FD_ISSET(m_sockfd, &readfds)) {
            uint8_t buf[4 * 1024] = {0};

            ssize_t got = ::read(m_sockfd, buf, sizeof(buf));

            if (got == 0) {
                std::cout << "EOF on socket\n";
                break;
            } else if (got == -1) {
                std::cout << "Socket error: " << errno << " " << std::strerror(errno) << "\n";
                exit(EXIT_FAILURE);
                continue;
            }

            try {
                client.received_data(buf, got);
            } catch (Botan::TLS::TLS_Exception &e) {
                std::cout << e.what() << std::endl;
                client.close();
                exit(e.error_code());
            }
        }
        if (client.timeout_check()) {
            std::cout << "Timeout detected\n";
        }
    }
    ::close(m_sockfd);
}
