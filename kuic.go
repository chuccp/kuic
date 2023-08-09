package net

import (
	"log"
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
		data := make([]byte, 1024)
		to, addr, err := bs.udpConn.ReadFrom(data)
		if err != nil {
			return
		} else {
			bb, rAddr, ok := bs.getBasicConn(data[0], addr)
			log.Println(bb, rAddr, ok)
			if ok {
				bb.handlePacket(&packet{num: to - 1, addr: rAddr, err: err, data: data[1:]})
			}
		}
	}
}
func (bs *baseServer) getServerConn() *basicConn {
	cn, ok := bs.basicConnMap[0]
	if ok {
		return cn
	}
	bc := NewServerConn(bs.udpConn)
	bs.basicConnMap[0] = bc
	return bc
}
func (bs *baseServer) getClientConn(addr *net.UDPAddr) *basicConn {
	bs.index++
	cc := NewClientConn(bs.udpConn, NewAddr(addr, bs.index&0x7F))
	bs.basicConnMap[bs.index] = cc
	return cc
}

type Listener struct {
	baseServer *baseServer
}

func (l *Listener) GetServerConn() *basicConn {
	return l.baseServer.getServerConn()
}
func (l *Listener) GetClientConn(rAddr *net.UDPAddr) *basicConn {
	return l.baseServer.getClientConn(rAddr)
}

func Listen(addr *net.UDPAddr) (*Listener, error) {
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	baseServer := &baseServer{udpConn: udpConn, basicConnMap: make(map[byte]*basicConn)}
	listener := &Listener{baseServer}
	go baseServer.run()
	return listener, nil
}
