#include "server.h"

std::string host = "127.0.0.1";
std::string servername = "tls-server.com";
std::vector<std::string> alpn = {"http/1.1"};
uint16_t port = 4433;

std::string cert = "/etc/ssl/cert-data/tls-server.com.crt";
std::string key = "/etc/ssl/cert-data/tls-server.com.pkcs8.key";
size_t max_clients = 5;
std::string transport = "tcp";

bool message_sent = false;
bool message_received = false;

std::list<std::string> m_pending_output;
std::string m_line_buf;
socket_type m_socket = -1;
size_t clients_served = 0;

class Basic_Credentials_Manager : public Botan::Credentials_Manager {
   public:
    Basic_Credentials_Manager(const std::string &ca_path) {
        if (ca_path.empty() == false) {
            m_certstores.push_back(std::make_shared<Botan::Certificate_Store_In_Memory>(ca_path));
        }
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

        // TODO: attempt to validate chain ourselves

        m_creds.push_back(cert);
    }

    std::vector<Botan::X509_Certificate> find_cert_chain(
        const std::vector<std::string> &key_types,
        const std::vector<Botan::X509_DN> &,
        const std::string &type,
        const std::string &context) override {
        return cert_chain(key_types, type, context);
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

        if (servername.compare(hostname) != 0) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::UNRECOGNIZED_NAME, "INVALID SNI");
        } else {
            std::cout << "SNI: " << servername << std::endl;
        }

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

    std::vector<Botan::X509_Certificate> cert_chain_single_type(
        const std::string &cert_key_type,
        const std::string &type,
        const std::string &context) {
        std::vector<std::string> cert_types;
        cert_types.push_back(cert_key_type);
        std::cout << context << std::endl;
        return find_cert_chain(cert_types, std::vector<Botan::X509_DN>(), type, context);
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

class Callbacks : public Botan::TLS::Callbacks {
   public:
    bool tls_session_established(const Botan::TLS::Session &session) override {
        //std::cout << "Handshake complete, " << session.version().to_string()
        //          << " using " << session.ciphersuite().to_string() << std::endl;

        if (!session.session_id().empty()) {
            //std::cout << "Session ID " << Botan::hex_encode(session.session_id()) << std::endl;
        }

        if (!session.session_ticket().empty()) {
            std::cout << "Session ticket " << Botan::hex_encode(session.session_ticket()) << std::endl;
        }

        message_received = false;
        message_sent = false;

        return true;
    }

    void tls_record_received(uint64_t, const uint8_t input[], size_t input_len) override {
        for (size_t i = 0; i != input_len; ++i) {
            const char c = static_cast<char>(input[i]);
            m_line_buf += c;
            if (c == '\n') {
                m_pending_output.push_back(m_line_buf);
                std::cout << m_line_buf << std::endl;
                m_line_buf.clear();
            }
        }
    }

    void tls_emit_data(const uint8_t buf[], size_t length) override {
        ssize_t sent = ::send(m_socket, buf, static_cast<sendrecv_len_type>(length), MSG_NOSIGNAL);

        if (sent == -1) {
            std::cout << "Error writing to socket - " << std::strerror(errno) << std::endl;
        } else if (sent != static_cast<ssize_t>(length)) {
            std::cout << "Packet of length " << length << " truncated to " << sent << std::endl;
        }
    }

    void tls_alert(Botan::TLS::Alert alert) override {
        std::cout << "Alert: " << alert.type_string() << std::endl;
    }

    std::string tls_server_choose_app_protocol(const std::vector<std::string> &client_protos) override {
        for (unsigned int i = 0; i < client_protos.size(); i++) {
            if (client_protos[i].compare(alpn[0]) == 0) {
                return client_protos[i];
            }
        }
        throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::NO_APPLICATION_PROTOCOL, "INVALID ALPN");
    }

    /*void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate> &cert_chain,
        const std::vector<std::shared_ptr<const Botan::OCSP::Response>> &ocsp_responses,
        const std::vector<Botan::Certificate_Store *> &trusted_roots,
        Botan::Usage_Type usage,
        const std::string &hostname,
        const Botan::TLS::Policy &policy) override
    {
        std::cout << hostname << "HOSTNAMEASDASDS" << std::endl;
        if (cert_chain.empty())
            throw Botan::Invalid_Argument("Certificate chain was empty");

        Botan::Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                                  policy.minimum_signature_strength());

        Botan::Path_Validation_Result result =
            x509_path_validate(cert_chain,
                               restrictions,
                               trusted_roots,
                               (usage ==  Botan::Usage_Type::TLS_SERVER_AUTH ? hostname : ""),
                               usage,
                               std::chrono::system_clock::now(),
                               tls_verify_cert_chain_ocsp_timeout(),
                               ocsp_responses);

        if (!result.successful_validation())
        {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BAD_CERTIFICATE,
                                "Certificate validation failure: " + result.result_string());
        }
    } */
};

int main(int argc, char **argv) {
    /* Get commandline arguments */
    int opt;
    while ((opt = getopt(argc, argv, "a:s:c:k:")) != -1) {
        switch (opt) {
            case 'a':
                alpn[0] = optarg;
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
            default:
                fprintf(stderr, "Usage: %s [-a alpn] [-s servername] [-c certfile] [-k keyfile] \n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    std::cout << "Parameters alpn=" << alpn[0] << " servername=" << servername << " cert=" << cert << " key=" << key << std::endl;

    Basic_TLS_Policy policy;

    Botan::AutoSeeded_RNG rng;
    Callbacks callbacks;
    Botan::TLS::Session_Manager_In_Memory session_manager(rng);

    Basic_Credentials_Manager creds(cert, key);

    //std::cout << "Listening for new connections on " << transport << " port " << port << std::endl;

    socket_type server_fd = make_server_socket(port);

    while (true) {
        m_socket = ::accept(server_fd, nullptr, nullptr);

        Botan::TLS::Server server(
            callbacks,
            session_manager,
            creds,
            policy,
            rng,
            false);

        try {
            while (!server.is_closed()) {
                try {
                    uint8_t buf[4 * 1024] = {0};
                    ssize_t got = ::recv(m_socket, Botan::cast_uint8_ptr_to_char(buf), sizeof(buf), 0);

                    if (got == -1) {
                        std::cerr << "Error in socket read - " << std::strerror(errno) << std::endl;
                        break;
                    }

                    if (got == 0) {
                        std::cerr << "EOF on socket" << std::endl;
                        break;
                    }

                    server.received_data(buf, got);

                    while (server.is_active() && !m_pending_output.empty()) {
                        std::string output = m_pending_output.front();
                        m_pending_output.pop_front();
                        //server.send(output);

                        if (!message_sent) {
                            std::string message = "Hello from Server!";
                            server.send(message);
                            message_sent = true;
                        }

                        if (output == "quit\n") {
                            server.close();
                        }
                    }

                } catch (std::exception &e) {
                    std::cerr << "Connection problem: " << e.what() << std::endl;
                    ::close(m_socket);
                    m_socket = -1;
                }
            }
        } catch (Botan::Exception &e) {
            std::cerr << "Connection failed: " << e.what() << "\n";
        }

        ::close(m_socket);
        m_socket = -1;
    }
    ::close(server_fd);
}