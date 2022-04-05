package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"runtime"
)

var servername = "tls-server.com"
var certificate = "certs/tls-server.com-chain.crt"
var privatekey = "certs/tls-server.com.key"
var port = ":4433"
var alpn = []string{"http/1.1"}

func main() {
	log.SetFlags(log.LstdFlags)

	println("Using GO:" + runtime.Version())

	// Get commandline arguments
	flag.StringVar(&servername, "s", "tls-server.com", "servername for SNI")
	flag.StringVar(&alpn[0], "a", "http/1.1", "ALPN")
	flag.StringVar(&certificate, "c", "/etc/ssl/cert-data/tls-server.com-chain.crt", "certifcate")
	flag.StringVar(&privatekey, "k", "/etc/ssl/cert-data/tls-server.com.key", "private key")
	flag.Parse()
	println("Parameters servername=" + servername + " alpn=" + alpn[0] + " cert=" + certificate + " key=" + privatekey)

	// Load certificate and private key
	cer, err := tls.LoadX509KeyPair(certificate, privatekey)
	if err != nil {
		log.Println(err)
		return
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		ServerName:   servername,
		NextProtos:   alpn,
	}

	if runtime.Version() < "go1.17" {
		println("Strict ALPN not implemented in go version. Overriding VerifyConnection")
		// Assign a custom function for VerifyConnection
		// if no ALPN is negotiated abort the handshake
		// 		it is not possible to access the protocol sent by the client if no ALPN could be negotiated
		//		so it's not possible to accept the connection if no ALPN is sent
		// if the wrong hostname is sent abort the connection
		// if no hostname is sent continue
		conf.VerifyConnection = func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol == "" {
				return errors.New("INVALID ALPN")
			} else if cs.ServerName != servername && len(cs.ServerName) > 0 {
				return errors.New("INVALID SNI: " + cs.ServerName)
			} else {
				log.Println("ALPN:", cs.NegotiatedProtocol)
				log.Println("SNI:", cs.ServerName)
				return nil
			}
		}
	} else {
		conf.VerifyConnection = func(cs tls.ConnectionState) error {
			if cs.ServerName != servername && len(cs.ServerName) > 0 {
				return errors.New("INVALID SNI: " + cs.ServerName)
			} else {
				return nil
			}
		}
	}

	// Listen for connections
	ln, err := tls.Listen("tcp", port, conf)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		// Receive message from Client
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		print(msg)

		// Send message to Client
		n, err := conn.Write([]byte("Hello from Server!\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}
