package http

import (
	"context"
	"crypto/tls"
	"github.com/chuccp/kuic"
	"github.com/quic-go/quic-go/http3"
	"net"
	"net/http"
)

type Server struct {
	addr       string
	baseServer kuic.BaseServer
	clientPool *ClientPool
}

func (server *Server) GetHttpClient(address string) (*Client, error) {
	return server.clientPool.GetHttpClient(address)
}

func (server *Server) ListenAndServeTLS(certFile, keyFile string, handler http.Handler) error {
	conn, err := server.baseServer.GetServerConn()
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if handler == nil {
		handler = http.DefaultServeMux
	}
	quicServer := &http3.Server{
		TLSConfig: config,
		Handler:   handler,
	}
	hErr := make(chan error)
	qErr := make(chan error)
	go func() {
		hErr <- http.ListenAndServeTLS(server.addr, certFile, keyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r)
		}))
	}()
	go func() {
		qErr <- quicServer.Serve(conn)
	}()
	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		return err
	}

	return nil
}
func (server *Server) ListenAndServe(certFile, keyFile string, handler http.Handler) error {
	conn, err := server.baseServer.GetServerConn()
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if handler == nil {
		handler = http.DefaultServeMux
	}
	quicServer := &http3.Server{
		TLSConfig: config,
		Handler:   handler,
	}
	hErr := make(chan error)
	qErr := make(chan error)
	go func() {
		hErr <- http.ListenAndServe(server.addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r)
		}))
	}()
	go func() {
		qErr <- quicServer.Serve(conn)
	}()
	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		return err
	}

	return nil
}
func CreateServer(addr string) (*Server, error) {
	server := &Server{addr: addr}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	server.baseServer = kuic.NewBaseServer(udpConn, context.Background())
	server.clientPool = NewClientPool(server.baseServer)
	return server, nil
}
