package kuic

import (
	"context"
	"net"
	"time"
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
	UDPConn         *net.UDPConn
	isClient        bool
	packetChan      chan *packet
	rAddr           net.Addr
	lAddr           net.Addr
	writeToFunc     WriteToFunc
	context         context.Context
	closeContext    context.Context
	closeCancelFunc context.CancelFunc
}

func NewBasicConn(conn *net.UDPConn, writeToFunc WriteToFunc, lAddr net.Addr, ctx context.Context) *basicConn {

	closeContext, closeCancelFunc := context.WithCancel(context.Background())

	return &basicConn{
		UDPConn:         conn,
		isClient:        false,
		lAddr:           lAddr,
		writeToFunc:     writeToFunc,
		packetChan:      make(chan *packet),
		context:         ctx,
		closeContext:    closeContext,
		closeCancelFunc: closeCancelFunc,
	}
}

func (c *basicConn) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}

func (c *basicConn) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *basicConn) SetReadDeadline(t time.Time) error {
	return c.UDPConn.SetReadDeadline(t)
}
func (c *basicConn) handlePacket(packet *packet) {
	c.packetChan <- packet
}
func (c *basicConn) Close() error {
	c.closeCancelFunc()
	return nil
}

func (c *basicConn) GetContext() context.Context {
	return c.context
}
func (c *basicConn) waitClose() {
	<-c.closeContext.Done()
}

func (c *basicConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.packetChan:
		{
			copy(p, packet.data)
			return packet.num, packet.addr, packet.err
		}
	case <-c.context.Done():
		return 0, nil, net.ErrClosed
	case <-c.closeContext.Done():
		return 0, nil, net.ErrClosed
	}
}

func (c *basicConn) WriteTo(ps []byte, rAddr net.Addr) (n int, err error) {
	addr, ok := rAddr.(*net.UDPAddr)
	if ok {
		if c.isClient {
			lAddr := c.lAddr.(*Addr)
			rAddr := NewAddr(addr, lAddr.seq&0x7F)
			return c.writeToFunc(ps, rAddr)
		} else {
			lAddr := c.lAddr.(*Addr)
			rAddr := NewAddr(addr, lAddr.seq|0x80)
			return c.writeToFunc(ps, rAddr)
		}
	}
	return c.writeToFunc(ps, rAddr)
}
func (c *basicConn) LocalAddr() net.Addr {
	return c.lAddr
}
