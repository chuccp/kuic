package net

import (
	"net"
	"strconv"
)

type Addr struct {
	net.Addr
	seq byte
}

func NewAddr(addr net.Addr, seq byte) *Addr {
	return &Addr{Addr: addr, seq: seq}
}
func (a *Addr) Network() string {
	return a.Addr.Network()
}
func (a *Addr) String() string {
	return a.Addr.String() + "_" + strconv.Itoa(int(a.seq))
}
