git clone https://github.com/tls-attacker/TLS-Scanner.git
cd TLS-Scanner
git submodule update --init --recursive
docker build . -t tlsscanner