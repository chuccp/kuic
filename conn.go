package net

import (
	"log"
	"net"
)

type packet struct {
	data []byte
	num  int
	err  error
	addr net.Addr
}

type basicConn struct {
	net.PacketConn
	isClient   bool
	packetChan chan *packet
	reAddr     *Addr
}

func NewServerConn(conn net.PacketConn) *basicConn {
	return &basicConn{isClient: false, PacketConn: conn, packetChan: make(chan *packet)}
}
func NewClientConn(conn net.PacketConn, reAddr *Addr) *basicConn {
	return &basicConn{isClient: true, PacketConn: conn, packetChan: make(chan *packet), reAddr: reAddr}
}
func (c *basicConn) handlePacket(packet *packet) {
	log.Println("handlePacket", "00000000", c)
	c.packetChan <- packet
	log.Println("handlePacket", "1111111", c)
}

func (c *basicConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	log.Println("ReadFrom", "00000000", c)
	packet := <-c.packetChan
	log.Println("ReadFrom", "11111111", c)
	copy(p, packet.data)
	return packet.num, packet.addr, packet.err
}

func (c *basicConn) WriteTo(ps []byte, addr net.Addr) (n int, err error) {
	a := addr.(*Addr)
	seq := a.seq
	data := append([]byte{seq}, ps...)
	log.Println(seq, string(ps))
	return c.PacketConn.WriteTo(data, a.Addr)
}
func (c *basicConn) Write(p []byte) (n int, err error) {
	if c.isClient {
		return c.WriteTo(p, c.reAddr)
	}
	return 0, err
}
func (c *basicConn) Close() error {
	return nil
}
func (c *basicConn) LocalAddr() net.Addr {
	return nil
}
