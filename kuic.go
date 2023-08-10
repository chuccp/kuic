package kuic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/quic-go/quic-go"
	"math/big"
	"net"
)

type baseServer struct {
	udpConn      *net.UDPConn
	basicConnMap map[byte]*basicConn
	index        byte
}

func (bs *baseServer) getBasicConn(b byte, addr net.Addr) (*basicConn, net.Addr, bool) {
	isServer := b&0x80 == 0
	if isServer {
		bc, ok := bs.basicConnMap[0]
		return bc, NewAddr(addr, b|0x80), ok
	} else {
		bc, ok := bs.basicConnMap[b&0x7F]
		return bc, NewAddr(addr, b&0x7F), ok
	}
}
func (bs *baseServer) run() {
	for {
		data := make([]byte, MaxPacketBufferSize)
		to, addr, err := bs.udpConn.ReadFrom(data)
		if err != nil {
			return
		} else {
			bb, rAddr, ok := bs.getBasicConn(data[0], addr)
			if ok {
				bb.handlePacket(&packet{num: to - 1, addr: rAddr, err: err, data: data[1:]})
			}
		}
	}
}

func (bs *baseServer) WriteTo(ps []byte, addr net.Addr) (n int, err error) {
	a := addr.(*Addr)
	seq := a.seq
	data := append([]byte{seq}, ps...)
	return bs.udpConn.WriteTo(data, a.Addr)
}
func (bs *baseServer) getServerConn() *basicConn {
	cn, ok := bs.basicConnMap[0]
	if ok {
		return cn
	}
	bc := NewServerConn(bs.udpConn, bs.WriteTo, NewAddr(bs.udpConn.LocalAddr(), 0))
	bs.basicConnMap[0] = bc
	return bc
}
func (bs *baseServer) getClientConn(addr *net.UDPAddr) (*basicConn, error) {
	bs.index++
	cc := NewClientConn(bs.udpConn, bs.WriteTo, NewAddr(bs.udpConn.LocalAddr(), bs.index|0x80), NewAddr(addr, bs.index))
	bs.basicConnMap[bs.index] = cc
	return cc, nil
}

type Listener struct {
	baseServer *baseServer
	listener   *quic.Listener
	context    context.Context
	cancelFunc context.CancelFunc
}

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
		NextProtos:   []string{"kuic"},
	}
}

func (l *Listener) Accept() (Connection, error) {
	conn, err := l.listener.Accept(l.context)
	if err != nil {
		return nil, err
	}
	return createConnection(conn, l.context), nil
}

func (l *Listener) getClientConn(rAddr *net.UDPAddr) (*basicConn, error) {
	return l.baseServer.getClientConn(rAddr)
}

func (l *Listener) Dial(addr *net.UDPAddr) (Connection, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"kuic"},
	}
	bc, err := l.getClientConn(addr)
	if err != nil {
		return nil, err
	}
	conn, err := quic.Dial(l.context, bc, bc.rAddr, tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return createConnection(conn, l.context), nil
}
func (l *Listener) Close() error {
	l.cancelFunc()
	return l.listener.Close()
}
func Listen(addr *net.UDPAddr) (*Listener, error) {
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	baseServer := &baseServer{udpConn: udpConn, basicConnMap: make(map[byte]*basicConn)}
	quicListener, err := quic.Listen(baseServer.getServerConn(), generateTLSConfig(), nil)
	if err != nil {
		return nil, err
	}
	context, contextCancelFunc := context.WithCancel(context.Background())
	listener := &Listener{baseServer, quicListener, context, contextCancelFunc}
	go baseServer.run()
	return listener, nil
}
