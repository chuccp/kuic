package http

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/chuccp/kuic"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

type ClientPool struct {
	lock       *sync.RWMutex
	baseServer kuic.BaseServer
	addressMap map[string]*Client
}

func (cp *ClientPool) GetHttpClient(address string) (*Client, error) {
	cp.lock.Lock()
	defer cp.lock.Unlock()
	client, ok := cp.addressMap[address]
	if ok {
		return client, nil
	}
	conn, err := cp.baseServer.GetClientConn()
	if err != nil {
		return nil, err
	}
	client = NewClient(address, conn)
	cp.addressMap[address] = client
	return client, nil

}

func NewClientPool(baseServer kuic.BaseServer) *ClientPool {
	return &ClientPool{lock: new(sync.RWMutex), baseServer: baseServer, addressMap: make(map[string]*Client)}
}

type Client struct {
	address string
	conn    net.PacketConn
	client  *http.Client
}

func (c *Client) Get(path string) (string, error) {
	get, err := c.GetRaw(path)
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
