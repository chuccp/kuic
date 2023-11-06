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
	lock            *sync.RWMutex
	baseServer      kuic.BaseServer
	addressMap      map[string]*Client
	connMap         map[string]net.PacketConn
	reverseProxyMap map[string]*ReverseProxy
}

func (cp *ClientPool) GetHttpClient(address string) (*Client, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	client, ok := cp.addressMap[address]
	if ok {
		return client, nil
	}
	conn, err := cp.getClientConn(address)
	if err != nil {
		return nil, err
	}
	client = NewClient(address, conn)
	cp.addressMap[address] = client
	return client, nil
}
func (cp *ClientPool) GetTlsHttpClient(address string, cert *cert.Certificate) (*Client, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	key := address + "_tls"
	client, ok := cp.addressMap[key]
	if ok {
		return client, nil
	}
	conn, err := cp.getClientConn(address)
	if err != nil {
		return nil, err
	}
	client = NewKuicClient(address, cert, conn)
	cp.addressMap[key] = client
	return client, nil
}
func (cp *ClientPool) ReverseProxy(address string) (*ReverseProxy, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	client, ok := cp.reverseProxyMap[address]
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
		cp.reverseProxyMap[address] = proxy
		return proxy, err
	}

}
func (cp *ClientPool) GetClientConn(address string) (net.PacketConn, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	return cp.getClientConn(address)
}
func (cp *ClientPool) getClientConn(address string) (net.PacketConn, error) {
	conn, ok := cp.connMap[address]
	if ok {
		return conn, nil
	}
	conn, err := cp.baseServer.GetClientConn()
	if err != nil {
		return nil, err
	}
	cp.connMap[address] = conn
	return conn, nil
}

func NewClientPool(baseServer kuic.BaseServer) *ClientPool {
	return &ClientPool{lock: new(sync.RWMutex), baseServer: baseServer, addressMap: make(map[string]*Client), connMap: make(map[string]net.PacketConn), reverseProxyMap: make(map[string]*ReverseProxy)}
}

type Client struct {
	address string
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
func (c *Client) GetRaw(path string) (io.ReadCloser, error) {
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	url := "https://" + c.address + "/" + path
	get, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	return get.Body, err
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
	url := "https://" + c.address + "/" + path
	body := bytes.NewReader(json)
	get, err := c.client.Post(url, "application/json", body)
	all, err := io.ReadAll(get.Body)
	if err != nil {
		return "", err
	}
	return string(all), nil
}

func NewClient(address string, conn net.PacketConn) *Client {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}
	cl := http3.NewClient(conn, tlsConf)
	return &Client{address: address, conn: conn, client: cl}
}
func NewKuicClient(address string, cer *cert.Certificate, conn net.PacketConn) *Client {

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(cer.ServerCa)
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*cer.Cert},
		RootCAs:            caCertPool,
		ClientCAs:          caCertPool,
		ServerName:         cer.ServerName,
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: false,
	}
	cl := http3.NewClient(conn, tlsConfig)
	return &Client{address: address, conn: conn, client: cl}
}
func NewTlsClient(address string, tlsConf *tls.Config, conn net.PacketConn) *Client {
	cl := http3.NewClient(conn, tlsConf)
	return &Client{address: address, conn: conn, client: cl}
}
