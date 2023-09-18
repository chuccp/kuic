package http

import (
	"crypto/tls"
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

func NewReverseProxy(remoteAddress string, conn net.PacketConn) (*ReverseProxy, error) {
	remoteUrl := "https://" + remoteAddress
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

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.reverseProxy.ServeHTTP(rw, req)
}
