package kuic

import (
	"log"
	"net"
	"testing"
	"time"
)

func TestName2(t *testing.T) {

	listen, err := Listen(&net.UDPAddr{IP: net.IPv4(192, 168, 1, 123), Port: 1235})
	if err != nil {
		t.Log(err)
	} else {
		go func() {
			conn, err := listen.Accept()
			if err != nil {
				return
			} else {
				stream, err := conn.AcceptStream()
				if err != nil {
					return
				} else {
					data := make([]byte, MaxPacketBufferSize)
					to, err := stream.Read(data)
					if err != nil {
						return
					}
					log.Println("ppp", string(data[:to]))

					stream.Write([]byte("!!!!!!!!!!!!"))
				}
			}
		}()
	}

	dial, err := listen.Dial(&net.UDPAddr{IP: net.IPv4(192, 168, 1, 123), Port: 1235})
	if err != nil {
		return
	}

	sync, err := dial.OpenStreamSync()
	if err != nil {
		return
	}
	sync.Write([]byte("22222222222222222"))
	data := make([]byte, MaxPacketBufferSize)
	to, err := sync.Read(data)
	if err != nil {
		return
	}
	log.Println("oooo", string(data[:to]))

	//listen.Close()

	time.Sleep(time.Second * 2)
}
