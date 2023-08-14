package http

import (
	"crypto/tls"
	"github.com/quic-go/quic-go/http3"
	"net"
	"net/http"
)

func ListenAndServe(addr, certFile, keyFile string, handler http.Handler) error {
	// Load certs
	var err error
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if addr == "" {
		addr = ":https"
	}

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	if handler == nil {
		handler = http.DefaultServeMux
	}
	// Start the servers
	quicServer := &http3.Server{
		TLSConfig: config,
		Handler:   handler,
	}

	hErr := make(chan error)
	qErr := make(chan error)
	go func() {
		hErr <- http.ListenAndServeTLS(addr, certFile, keyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			quicServer.SetQuicHeaders(w.Header())
			handler.ServeHTTP(w, r)
		}))
	}()
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}
