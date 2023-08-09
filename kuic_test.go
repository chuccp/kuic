package net

import (
	"log"
	"net"
	"testing"
	"time"
)

func TestName(t *testing.T) {
	listen, err := Listen(&net.UDPAddr{IP: net.IPv4zero, Port: 1235})
	if err != nil {
		return
	}
	server := listen.GetServerConn()
	go func() {
		for {
			data := make([]byte, 1024)
			to, addr, err := server.ReadFrom(data)
			if err != nil {
				log.Println("------", err)
				return
			} else {
				log.Println("===========", string(data[:to]), addr)
				_, err := server.WriteTo([]byte("ooooooooooo"), addr)
				if err != nil {
					log.Println("------", err)
					return
				}
			}
		}

	}()

	packetConn := listen.GetClientConn(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1235})
	_, err = packetConn.Write([]byte("5555555555555"))
	if err != nil {
		log.Println("============", err)
		return
	}
	data := make([]byte, 1024)
	log.Println("xxxxxxxx", err)
	to, addr, err := packetConn.ReadFrom(data)
	log.Println("===========", string(data[:to]), addr)
	time.Sleep(time.Second * 10)
}
