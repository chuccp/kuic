package kuic

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/quic-go/quic-go"
	"log"
	"math/big"
	"net"
	"sync"
)

type seqStack struct {
	l      *list.List
	locker *sync.Mutex
}

var ErrConnNumOver = errors.New("conn number Over")

func (s *seqStack) init() {
	num := int(MaxSeqNum)
	for i := 0; i <= num; i++ {
		s.l.PushBack(byte(i))
	}
}

func (s *seqStack) pop() (byte, error) {
	s.locker.Lock()
	defer s.locker.Unlock()
	if s.l.Len() == 0 {
		return 0, ErrConnNumOver
	}
	return s.l.Front().Value.(byte), nil
}

func (s *seqStack) push(seq byte) {
	s.locker.Lock()
	defer s.locker.Unlock()
	s.l.PushBack(seq)
}

func newSeqStack() *seqStack {
	seqStack := &seqStack{l: new(list.List), locker: new(sync.Mutex)}
	seqStack.init()
	return seqStack
}

type BaseServer interface {
	GetServerConn() (net.PacketConn, error)
	GetClientConn(rAddr *net.UDPAddr) (net.PacketConn, error)
}

type baseServer struct {
	udpConn      *net.UDPConn
	basicConnMap map[byte]*basicConn
	serverConn   *basicConn
	seqStack     *seqStack
	context      context.Context
	listener     *quic.Listener
	locker       *sync.Mutex
}

func NewBaseServer(udpConn *net.UDPConn, context context.Context) *baseServer {
	baseServer := &baseServer{udpConn: udpConn, basicConnMap: make(map[byte]*basicConn), seqStack: newSeqStack(), context: context, locker: new(sync.Mutex)}
	go baseServer.run()
	return baseServer
}
func (bs *baseServer) getBasicConn(b byte, addr net.Addr) (*basicConn, net.Addr, bool) {
	isServer := b&0x80 == 0
	if isServer {
		return bs.serverConn, NewAddr(addr, b|0x80), bs.serverConn != nil
	} else {
		bc, ok := bs.basicConnMap[b]
		return bc, NewAddr(addr, b&0x7F), ok
	}
}
func (bs *baseServer) run() {
	log.Println("============================")
	for {
		data := make([]byte, MaxPacketBufferSize)
		to, addr, err := bs.udpConn.ReadFrom(data)
		log.Println(data[:to])
		if err != nil {
			return
		} else {
			bb, rAddr, ok := bs.getBasicConn(data[to-1], addr)
			if ok {
				bb.handlePacket(&packet{num: to - 1, addr: rAddr, err: err, data: data})
			}
		}
	}
}

func (bs *baseServer) WriteTo(ps []byte, addr net.Addr) (n int, err error) {
	a := addr.(*Addr)
	seq := a.seq
	data := append(ps, seq)
	return bs.udpConn.WriteTo(data, a.Addr)
}
func (bs *baseServer) GetServerConn() (net.PacketConn, error) {
	bs.locker.Lock()
	defer bs.locker.Unlock()
	if bs.serverConn != nil {
		return bs.serverConn, errors.New(" only can get once")
	}
	bc := NewServerConn(bs.udpConn, bs.WriteTo, NewAddr(bs.udpConn.LocalAddr(), 0), bs.context)
	bs.serverConn = bc
	return bc, nil
}
func (bs *baseServer) close() error {
	return bs.listener.Close()
}

func (bs *baseServer) accept() (Connection, error) {
	conn, err := bs.listener.Accept(bs.context)
	if err != nil {
		return nil, err
	}
	return createConnection(conn, bs.context), nil
}

func (bs *baseServer) dial(rAddr *net.UDPAddr) (Connection, error) {
	seq, err := bs.seqStack.pop()
	if err != nil {
		return nil, err
	}
	lSeq := seq | 0x80
	clientConn := NewClientConn(bs.udpConn, bs.WriteTo, NewAddr(bs.udpConn.LocalAddr(), lSeq), NewAddr(rAddr, seq), bs.context)
	bs.basicConnMap[lSeq] = clientConn
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"kuic"},
	}
	conn, err := quic.Dial(bs.context, clientConn, clientConn.rAddr, tlsConf, nil)
	if err != nil {
		bs.seqStack.push(seq)
		return nil, err
	}
	go func() {
		<-conn.Context().Done()
		bs.seqStack.push(seq)
	}()
	return createConnection(conn, bs.context), nil
}

func (bs *baseServer) getClientConn(rAddr *net.UDPAddr) (Connection, error) {
	seq, err := bs.seqStack.pop()
	if err != nil {
		return nil, err
	}
	lSeq := seq | 0x80
	clientConn := NewClientConn(bs.udpConn, bs.WriteTo, NewAddr(bs.udpConn.LocalAddr(), lSeq), NewAddr(rAddr, seq), bs.context)
	bs.basicConnMap[lSeq] = clientConn
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"kuic"},
	}
	conn, err := quic.Dial(bs.context, clientConn, clientConn.rAddr, tlsConf, nil)
	if err != nil {
		bs.seqStack.push(seq)
		return nil, err
	}
	go func() {
		select {
		case <-conn.Context().Done():
		case <-clientConn.GetContext().Done():
		}
		bs.seqStack.push(seq)
	}()
	return createConnection(conn, bs.context), nil
}

func (bs *baseServer) GetClientConn(rAddr *net.UDPAddr) (net.PacketConn, error) {
	seq, err := bs.seqStack.pop()
	if err != nil {
		return nil, err
	}
	lSeq := seq | 0x80
	clientConn := NewClientConn(bs.udpConn, bs.WriteTo, NewAddr(bs.udpConn.LocalAddr(), lSeq), NewAddr(rAddr, seq), bs.context)
	go func() {
		clientConn.waitClose()
		bs.seqStack.push(seq)
	}()
	return clientConn, nil
}

type Listener struct {
	baseServer *baseServer
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
	return l.baseServer.accept()
}

func (l *Listener) Dial(addr *net.UDPAddr) (Connection, error) {
	return l.baseServer.dial(addr)
}
func (l *Listener) Close() error {
	l.cancelFunc()
	return l.baseServer.close()
}

func (l *Listener) GetServerConn() (net.PacketConn, error) {
	return l.baseServer.GetServerConn()
}
func (l *Listener) GetClientConn(addr *net.UDPAddr) (net.PacketConn, error) {
	return l.baseServer.GetClientConn(addr)
}
func Listen(addr *net.UDPAddr) (*Listener, error) {
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	context, contextCancelFunc := context.WithCancel(context.Background())
	baseServer := NewBaseServer(udpConn, context)
	conn, err := baseServer.GetServerConn()
	if err != nil {
		return nil, err
	}
	listen, err := quic.Listen(conn, generateTLSConfig(), nil)
	if err != nil {
		return nil, err
	}
	baseServer.listener = listen
	listener := &Listener{baseServer, context, contextCancelFunc}
	return listener, nil
}
