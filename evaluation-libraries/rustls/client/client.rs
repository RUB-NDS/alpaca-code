extern crate clap;
use clap::{Arg, App};

use std::sync::Arc;

use mio;
use mio::net::{TcpStream};
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};

use std::process;
use std::collections;
use rustls;
use rustls::{RootCertStore};
use std::sync::Mutex;
use std::convert::TryFrom;

const CLIENT: mio::Token = mio::Token(0);

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::ClientConnection,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
    ) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn ready(&mut self, ev: &mio::event::Event) {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            self.do_read();
        }

        if ev.is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = Vec::new();
            plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
            self.tls_conn
                .reader()
                .read(&mut plaintext)
                .unwrap();
            io::stdout()
                .write_all(&plaintext)
                .unwrap();
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
            return;
        }
    }

    fn do_write(&mut self) {
        self.tls_conn
            .write_tls(&mut self.socket)
            .unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .register(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .reregister(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn _new(filename: &Option<String>) -> Self {
        let cache = PersistCache {
            cache: Mutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::Codec;

        if self.filename.is_none() {
            return;
        }

        let mut file =
            fs::File::create(self.filename.as_ref().unwrap()).expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::{Codec, Reader};

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::client::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache
            .lock()
            .unwrap()
            .insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
    }
}

// TODO: um, well, it turns out that openssl s_client/s_server
// that we use for testing doesn't do ipv6.  So we can't actually
// test ipv6 and hence kill this.
fn lookup_ipv4(host: &str, port: u16) -> std::net::SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let std::net::SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

#[cfg(feature = "dangerous_configuration")]
mod danger {
    use super::rustls;

    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

// #[cfg(feature = "dangerous_configuration")]
// fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
//     if args.flag_insecure {
//         cfg.dangerous()
//             .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
//     }
// }

// #[cfg(not(feature = "dangerous_configuration"))]
// fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
//     if args.flag_insecure {
//         panic!("This build does not support --insecure.");
//     }
// }

/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn main() {
    let matches = App::new("alpaca-rustls")
                        .version("1.0")
                        .arg(Arg::with_name("cert")
                            .short("c")
                            .long("cert")
                            .takes_value(true))
                        .arg(Arg::with_name("host")
                            .short("h")
                            .long("host")
                            .takes_value(true))
                        .arg(Arg::with_name("servername")
                            .short("s")
                            .long("servername")
                            .takes_value(true))
                        .arg(Arg::with_name("alpn")
                            .short("a")
                            .long("alpn")
                            .takes_value(true))
                        .get_matches();

    let cert = matches.value_of("cert").unwrap_or("/etc/ssl/cert-data/ca.crt");
    let host = matches.value_of("host").unwrap_or("127.0.0.1");
    let servername = matches.value_of("servername").unwrap_or("tls-server.com");
    let alpn = matches.value_of("alpn").unwrap_or("http/1.1");

    println!("Parameters alpn={} servername={} cert={} host={} port={} ", alpn, servername, cert, host, "4433");

    let addr = lookup_ipv4(host, 4433);

    let mut root_store = RootCertStore::empty();
    let certfile = fs::File::open(&cert).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());

    let suites = rustls::ALL_CIPHER_SUITES.to_vec();
    let versions = rustls::DEFAULT_VERSIONS.to_vec();

    let mut config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    //config.enable_sni = false;

    config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    //config.max_fragment_size = args.flag_max_frag_size;

    //apply_dangerous_options(args, &mut config);

    let test = Arc::new(config);


    let sock = TcpStream::connect(addr).unwrap();
    let dnslookup = rustls::ServerName::try_from(servername).expect("invalid DNS name");

    // let server_name = args
    //     .arg_hostname
    //     .as_str()
    //     .try_into()
    //     .expect("invalid DNS name");
    let mut tlsclient = TlsClient::new(sock, dnslookup, test);

    let message = format!("Hello from Client!\n");
    tlsclient
        .write_all(message.as_bytes())
        .unwrap();

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(32);
    tlsclient.register(poll.registry());

    loop {
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            tlsclient.ready(&ev);
            tlsclient.reregister(poll.registry());
        }
    }
}