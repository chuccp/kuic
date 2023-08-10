package kuic

import (
	"github.com/quic-go/quic-go"
	"log"
	"testing"
)

func TestName(t *testing.T) {

	addr, err := quic.ListenAddr("0.0.0.0:5656", generateTLSConfig(), nil)
	if err != nil {
		log.Println(err)
		return
	}
	err = addr.Close()
	if err != nil {
		log.Println(err)
		return
	}
}
