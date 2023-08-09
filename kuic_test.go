package net

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/quic-go/quic-go"
	"log"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func TestName(t *testing.T) {
	listen, err := Listen(&net.UDPAddr{IP: net.IPv4zero, Port: 1235})
	if err != nil {
		return
	}
	server := listen.GetServerConn()

	listener, err := quic.Listen(server, generateTLSConfig(), nil)
	if err != nil {
		log.Println(err)
		return
	}

	go func() {
		for {

			accept, err := listener.Accept(context.Background())
			if err != nil {
				return
			} else {

				stream, err := accept.AcceptStream(accept.Context())
				if err != nil {
					return
				}
				data := make([]byte, 1024)
				read, err := stream.Read(data)
				if err != nil {
					return
				} else {
					log.Println("1111", string(data[:read]))
				}

			}

		}

	}()

	packetConn := listen.GetClientConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1235})

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	dial, err := quic.Dial(context.Background(), packetConn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1235}, tlsConf, nil)
	if err != nil {
		log.Println(err)
		return
	}
	sync, err := dial.OpenStreamSync(context.Background())
	if err != nil {
		return
	}
	sync.Write([]byte("4444444444444444444444444"))
	time.Sleep(time.Second * 5)
}
