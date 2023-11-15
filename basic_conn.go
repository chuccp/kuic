package kuic

import (
	"context"
	"errors"
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

type BasicConn struct {
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

	timeOutCloseContext    context.Context
	timeOutCloseCancelFunc context.CancelFunc
}

func NewBasicConn(conn *net.UDPConn, writeToFunc WriteToFunc, lAddr net.Addr, ctx context.Context) *BasicConn {

	closeContext, closeCancelFunc := context.WithCancel(context.Background())

	return &BasicConn{
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

func (c *BasicConn) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}

func (c *BasicConn) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *BasicConn) SetReadDeadline(t time.Time) error {
	if c.timeOutCloseContext != nil && c.timeOutCloseContext.Err() == nil {
		c.timeOutCloseCancelFunc()
	}
	if c.closeContext.Err() != nil {
		return c.closeContext.Err()
	}
	c.timeOutCloseContext, c.timeOutCloseCancelFunc = context.WithDeadline(context.Background(), t)
	go func() {
		select {
		case <-c.timeOutCloseContext.Done():
			{
				err := c.timeOutCloseContext.Err()
				if errors.Is(err, context.DeadlineExceeded) {
					c.Close()
				}
			}
		}
	}()
	return nil
}
func (c *BasicConn) handlePacket(packet *packet) {
	c.packetChan <- packet
}
func (c *BasicConn) Close() error {
	c.closeCancelFunc()
	return nil
}

func (c *BasicConn) GetContext() context.Context {
	return c.context
}
func (c *BasicConn) WaitClose() {
	<-c.closeContext.Done()
}

func (c *BasicConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-c.packetChan:
		{
			copy(p, packet.data)
			return packet.num, packet.addr, packet.err
		}
	case <-c.context.Done():
		c.Close()
		return 0, nil, net.ErrClosed
	case <-c.closeContext.Done():
		return 0, nil, net.ErrClosed
	}
}

func (c *BasicConn) WriteTo(ps []byte, rAddr net.Addr) (n int, err error) {
	addr, ok := rAddr.(*net.UDPAddr)
	if ok {
		if c.isClient {
			lAddr := c.lAddr.(*Addr)
			rAddr := NewAddr(addr, lAddr.seq&0x7FFF)
			return c.writeToFunc(ps, rAddr)
		} else {
			lAddr := c.lAddr.(*Addr)
			rAddr := NewAddr(addr, lAddr.seq|0x8000)
			return c.writeToFunc(ps, rAddr)
		}
	}
	return c.writeToFunc(ps, rAddr)
}
func (c *BasicConn) LocalAddr() net.Addr {
	return c.lAddr
}
