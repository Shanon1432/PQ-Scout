// pqtls: one TLS 1.3 handshake on loopback with a chosen key-exchange
// group, so PQ-Scout can be tested against a REAL post-quantum hybrid
// handshake (X25519MLKEM768), not just classical ones.
//
// OpenSSL 3.0 (used for the main 41-case batch) cannot negotiate ML-KEM.
// Go's crypto/tls supports X25519MLKEM768 natively from Go 1.24, so it is
// used here as the ground-truth generator for the post-quantum path.
//
// usage: go run pqtls.go -port 19443 -server mlkem -client mlkem,x25519
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

func curves(spec string) []tls.CurveID {
	var out []tls.CurveID
	for _, name := range strings.Split(spec, ",") {
		switch strings.TrimSpace(name) {
		case "mlkem":
			out = append(out, tls.X25519MLKEM768)
		case "x25519":
			out = append(out, tls.X25519)
		case "p256":
			out = append(out, tls.CurveP256)
		}
	}
	return out
}

func selfSigned() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqscout-lab.local"},
		DNSNames:     []string{"pqscout-lab.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	port := flag.Int("port", 19443, "loopback port")
	srvSpec := flag.String("server", "mlkem", "server group preference list")
	cliSpec := flag.String("client", "mlkem", "client group preference list")
	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates:     []tls.Certificate{selfSigned()},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves(*srvSpec),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 16)
		c.Read(buf)
		c.Write([]byte("ok"))
		c.Close()
	}()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "pqscout-lab.local",
		InsecureSkipVerify: true, // lab self-signed cert; only the handshake matters
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   curves(*cliSpec),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	conn.Write([]byte("hello"))
	buf := make([]byte, 16)
	conn.Read(buf)
	st := conn.ConnectionState()
	// Go 1.24 does not expose the negotiated group in ConnectionState, so
	// the group's ground truth comes from construction instead: the server
	// is configured to accept exactly ONE group, so a successful handshake
	// can only have used that group.
	fmt.Printf("negotiated version=%s cipher=%s\n",
		tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
	conn.Close()
	<-done
	ln.Close()
}
