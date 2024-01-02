package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/chuccp/kuic"
	"github.com/chuccp/kuic/cert"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

type ClientPool struct {
	lock               *sync.RWMutex
	baseServer         kuic.BaseServer
	addressMap         map[string]*Client
	connMap            map[string]*kuic.BasicConn
	reverseProxyMap    map[string]*ReverseProxy
	tlsReverseProxyMap map[string]*ReverseProxy
}

func (cp *ClientPool) GetHttpClient(address *net.UDPAddr) (*Client, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	key := address.String()
	client, ok := cp.addressMap[key]
	if ok {
		return client, nil
	}
	conn, err := cp.getClientConn(address)
	if err != nil {
		return nil, err
	}
	client = NewClient(address, conn)
	cp.addressMap[key] = client
	go func() {
		conn.WaitClose()
		delete(cp.addressMap, key)
	}()
	return client, nil
}
func (cp *ClientPool) GetTlsHttpClient(address *net.UDPAddr, cert *cert.Certificate) (*Client, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	addressStr := address.String()
	key := addressStr + "_tls"
	client, ok := cp.addressMap[key]
	if ok {
		return client, nil
	}
	conn, err := cp.getClientTlsConn(addressStr)
	if err != nil {
		return nil, err
	}
	client = NewKuicClient(address, cert, conn)
	cp.addressMap[key] = client
	go func() {
		conn.WaitClose()
		delete(cp.addressMap, key)
	}()
	return client, nil
}
func (cp *ClientPool) ReverseProxy(address *net.UDPAddr) (*ReverseProxy, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	addressStr := address.String()
	client, ok := cp.reverseProxyMap[addressStr]
	if ok {
		return client, nil
	}
	conn, err := cp.getClientConn(address)
	if err != nil {
		return nil, err
	} else {
		proxy, err := NewReverseProxy(address, conn)
		if err != nil {
			return nil, err
		}
		cp.reverseProxyMap[addressStr] = proxy
		go func() {
			conn.WaitClose()
			delete(cp.reverseProxyMap, addressStr)
		}()
		return proxy, err
	}

}
func (cp *ClientPool) TlsReverseProxy(address *net.UDPAddr, cert *cert.Certificate) (*ReverseProxy, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	addressStr := address.String()
	client, ok := cp.tlsReverseProxyMap[addressStr]
	if ok {
		return client, nil
	}
	conn, err := cp.getClientTlsConn(addressStr)
	if err != nil {
		return nil, err
	} else {
		proxy, err := NewTslReverseProxy(address, conn, cert)
		if err != nil {
			return nil, err
		}
		cp.tlsReverseProxyMap[addressStr] = proxy
		go func() {
			conn.WaitClose()
			delete(cp.tlsReverseProxyMap, addressStr)
		}()
		return proxy, err
	}

}

func (cp *ClientPool) GetClientConn(address *net.UDPAddr) (net.PacketConn, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	return cp.getClientConn(address)
}
func (cp *ClientPool) getClientConn(address *net.UDPAddr) (*kuic.BasicConn, error) {
	key := address.String()
	conn, ok := cp.connMap[key]
	if ok {
		return conn, nil
	}
	conn, err := cp.baseServer.GetClientConn()
	if err != nil {
		return nil, err
	}
	go func() {
		conn.WaitClose()
		delete(cp.connMap, key)
	}()
	cp.connMap[key] = conn
	return conn, nil
}
func (cp *ClientPool) getClientTlsConn(address string) (*kuic.BasicConn, error) {
	key := address + "_tls"
	conn, ok := cp.connMap[key]
	if ok {
		return conn, nil
	}
	conn, err := cp.baseServer.GetClientConn()
	if err != nil {
		return nil, err
	}
	go func() {
		conn.WaitClose()
		delete(cp.connMap, key)
	}()
	cp.connMap[key] = conn
	return conn, nil
}

func NewClientPool(baseServer kuic.BaseServer) *ClientPool {
	return &ClientPool{lock: new(sync.RWMutex), baseServer: baseServer, addressMap: make(map[string]*Client), connMap: make(map[string]*kuic.BasicConn), tlsReverseProxyMap: make(map[string]*ReverseProxy), reverseProxyMap: make(map[string]*ReverseProxy)}
}

type Client struct {
	address *net.UDPAddr
	conn    net.PacketConn
	client  *http.Client
}

func (c *Client) Get(path string) (string, error) {
	get, err := c.GetRaw(path)
	if err != nil {
		return "", err
	}
	all, err := io.ReadAll(get)
	if err != nil {
		return "", err
	}
	return string(all), nil
}

func (c *Client) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}
func (c *Client) Close() {
	v := c.client.Transport.(*http3.RoundTripper)
	v.Close()
}

func (c *Client) GetRaw(path string) (io.ReadCloser, error) {
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	address := c.address.String()
	url := "https://" + address + "/" + path
	get, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	return get.Body, err
}
func (c *Client) GetResponse(path string) (*http.Response, error) {
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	address := c.address.String()
	url := "https://" + address + "/" + path
	resp, err := c.client.Get(url)
	return resp, err
}
func (c *Client) PostJson(path string, value any) (string, error) {
	switch i := value.(type) {
	case string:
		return c.PostJsonRaw(path, []byte(i))
	case []byte:
		return c.PostJsonRaw(path, i)
	default:
		marshal, err := json.Marshal(value)
		if err != nil {
			return "", err
		} else {
			return c.PostJsonRaw(path, marshal)
		}
	}
}

func (c *Client) PostJsonString(path string, json string) (string, error) {
	return c.PostJsonRaw(path, []byte(json))
}
func (c *Client) PostJsonRaw(path string, json []byte) (string, error) {
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	address := c.address.String()
	url := "https://" + address + "/" + path
	body := bytes.NewReader(json)
	get, err := c.client.Post(url, "application/json", body)
	if err != nil {
		return "", err
	}
	all, err := io.ReadAll(get.Body)
	if err != nil {
		return "", err
	}
	return string(all), nil
}

func NewClient(address *net.UDPAddr, conn net.PacketConn) *Client {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}
	cl := http3.NewClient(conn, tlsConf)
	return &Client{address: address, conn: conn, client: cl}
}
func NewKuicClient(address *net.UDPAddr, cer *cert.Certificate, conn net.PacketConn) *Client {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cer.CaPem)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cer.Cert},
		RootCAs:      caCertPool,
		//ClientCAs:          caCertPool,
		ServerName:         cer.ServerName,
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: false,
	}
	cl := http3.NewClient(conn, tlsConfig)
	return &Client{address: address, conn: conn, client: cl}
}
func NewTlsClient(address *net.UDPAddr, tlsConf *tls.Config, conn net.PacketConn) *Client {
	cl := http3.NewClient(conn, tlsConf)
	return &Client{address: address, conn: conn, client: cl}
}
