package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
)

var servername string
var certificate string
var host string = "127.0.0.1"
var port string = "4433"
var alpn = []string{""}

func main() {
	log.SetFlags(log.LstdFlags)

	// Get commandline arguments
	flag.StringVar(&servername, "s", "tls-server.com", "servername for SNI")
	flag.StringVar(&alpn[0], "a", "http/1.1", "ALPN")
	flag.StringVar(&certificate, "c", "/etc/ssl/certs/ca.crt", "certicate")
	flag.StringVar(&host, "h", "127.0.0.1", "host")
	flag.StringVar(&port, "p", "4433", "port")
	flag.Parse()
	println("Parameters servername=" + servername + " alpn=" + alpn[0] + " cert=" + certificate + " host=" + host + " port=" + port)

	certs := x509.NewCertPool()

	// Read Certificate
	pemData, err := ioutil.ReadFile(certificate)
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	certs.AppendCertsFromPEM(pemData)

	// Setup TLS config
	conf := &tls.Config{
		RootCAs:    certs,
		NextProtos: alpn,
		ServerName: servername,
	}
	if runtime.Version() < "go1.17" {
		println("Strict ALPN not implemented in go version. Overriding VerifyConnection")
		conf.VerifyConnection = func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol == "" {
				return errors.New("INVALID ALPN")
			} else {
				log.Println("ALPN:", cs.NegotiatedProtocol)
				return nil
			}
		}
	}

	// Connect to host
	conn, err := tls.Dial("tcp", host+":"+port, conf)
	if err != nil {
		log.Println(err)
		if strings.Contains(err.Error(), "server selected unadvertised ALPN protocol") {
			os.Exit(120)
		} else if strings.Contains(err.Error(), "x509: certificate is valid for") {
			os.Exit(42)
		}
		os.Exit(1)
	}

	// Send message to server
	n, err := conn.Write([]byte("Hello from Client!\n"))
	if err != nil {
		log.Println(n, err)
		os.Exit(2)
		return
	}

	// Receive message from server
	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		os.Exit(3)
		return
	}
	print(string(buf[:n]))

	defer conn.Close()
	os.Exit(0)
}
