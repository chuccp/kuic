package kuic

import (
	"log"
	"net"
	"testing"
	"time"
)

func TestName2(t *testing.T) {
	port := 1256

	listen, err := Listen(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Log(err)
		return
	} else {
		go func() {
			conn, err := listen.Accept()
			if err != nil {
				t.Log(err)
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
					log.Println("===============")
				}
			}
		}()
	}

	dial, err := listen.Dial(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Log(err)
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

	dial.Close()

	time.Sleep(time.Second * 10)
}
