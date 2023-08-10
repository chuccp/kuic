package kuic

import (
	"net"
)

type WriteToFunc func(ps []byte, addr net.Addr) (n int, err error)

type packet struct {
	data []byte
	num  int
	err  error
	addr net.Addr
}

type basicConn struct {
	net.PacketConn
	UDPConn     *net.UDPConn
	isClient    bool
	packetChan  chan *packet
	rAddr       net.Addr
	lAddr       net.Addr
	writeToFunc WriteToFunc
}

func NewServerConn(conn *net.UDPConn, writeToFunc WriteToFunc, lAddr net.Addr) *basicConn {
	return &basicConn{UDPConn: conn, isClient: false, lAddr: lAddr, writeToFunc: writeToFunc, packetChan: make(chan *packet)}
}
func NewClientConn(conn *net.UDPConn, writeToFunc WriteToFunc, lAddr net.Addr, rAddr net.Addr) *basicConn {
	return &basicConn{UDPConn: conn, isClient: true, lAddr: lAddr, writeToFunc: writeToFunc, packetChan: make(chan *packet), rAddr: rAddr}
}
func (c *basicConn) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}
func (c *basicConn) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *basicConn) handlePacket(packet *packet) {
	c.packetChan <- packet
}

func (c *basicConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet := <-c.packetChan
	copy(p, packet.data)
	return packet.num, packet.addr, packet.err
}

func (c *basicConn) WriteTo(ps []byte, addr net.Addr) (n int, err error) {
	return c.writeToFunc(ps, addr)
}
func (c *basicConn) LocalAddr() net.Addr {
	return c.lAddr
}
