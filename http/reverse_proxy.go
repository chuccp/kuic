package http

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/chuccp/kuic/cert"
	"github.com/quic-go/quic-go/http3"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type ReverseProxy struct {
	remoteUrl    *url.URL
	reverseProxy *httputil.ReverseProxy
}

func NewReverseProxy(remoteAddress *net.UDPAddr, conn net.PacketConn) (*ReverseProxy, error) {
	remoteUrl := "https://" + remoteAddress.String()
	parseUrl, err := url.Parse(remoteUrl)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}
	roundTripper := http3.GetTransport(conn, tlsConf)
	reverseProxy := httputil.NewSingleHostReverseProxy(parseUrl)
	reverseProxy.Transport = roundTripper
	return &ReverseProxy{reverseProxy: reverseProxy, remoteUrl: parseUrl}, nil
}

func NewTslReverseProxy(remoteAddress *net.UDPAddr, conn net.PacketConn, cert *cert.Certificate) (*ReverseProxy, error) {
	remoteUrl := "https://" + remoteAddress.String()
	parseUrl, err := url.Parse(remoteUrl)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cert.CaPem)
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*cert.Cert},
		RootCAs:            caCertPool,
		ClientCAs:          caCertPool,
		ServerName:         cert.ServerName,
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: false,
	}
	roundTripper := http3.GetTransport(conn, tlsConfig)
	reverseProxy := httputil.NewSingleHostReverseProxy(parseUrl)
	reverseProxy.Transport = roundTripper
	return &ReverseProxy{reverseProxy: reverseProxy, remoteUrl: parseUrl}, nil
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.reverseProxy.ServeHTTP(rw, req)
}
