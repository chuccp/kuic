package kuic

import (
	"net"
	"strconv"
	"strings"
)

type Addr struct {
	net.Addr
	seq uint16
}

func NewAddr(addr net.Addr, seq uint16) *Addr {
	return &Addr{Addr: addr, seq: seq}
}
func (a *Addr) Network() string {
	return a.Addr.Network()
}
func (a *Addr) String() string {
	addr := a.Addr.String()
	if strings.Contains(addr, "]") {
		return strings.ReplaceAll(addr, "]", "%"+strconv.Itoa(int(a.seq))+"]")
	}
	return addr + "_" + strconv.Itoa(int(a.seq))
}
