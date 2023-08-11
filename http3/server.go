package http3

import (
	"crypto/tls"
	"github.com/chuccp/kuic"
	"github.com/quic-go/quic-go/http3"
	"net"
	"net/http"
)

type Server struct {
	serveMux *http.ServeMux
	addr     string
	listener *kuic.Listener
}

func (server *Server) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	server.serveMux.HandleFunc(pattern, handler)
}
func (server *Server) Listen(certFile, keyFile string) error {
	conn, err := server.listener.GetServerConn()
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
	quicServer := &http3.Server{
		TLSConfig: config,
		Handler:   server.serveMux,
	}
	hErr := make(chan error)
	qErr := make(chan error)
	go func() {
		hErr <- http.ListenAndServeTLS(server.addr, certFile, keyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			quicServer.SetQuicHeaders(w.Header())
			server.serveMux.ServeHTTP(w, r)
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

func createServer(addr string) (*Server, error) {
	server := &Server{addr: addr, serveMux: http.NewServeMux()}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	listen, err := kuic.Listen(udpAddr)
	if err != nil {
		return nil, err
	}
	server.listener = listen
	return server, nil
}
