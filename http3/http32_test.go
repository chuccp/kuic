package http

import (
	"github.com/chuccp/kuic/cert"
	"github.com/quic-go/quic-go/http3"
	"log"
	"net/http"
	"testing"
)

func TestName(t *testing.T) {

	keyPem := "key2.PEM"
	certPem := "cert2.PEM"
	err := cert.CreateOrReadCert(keyPem, certPem)
	if err != nil {
		log.Println(err)
		return
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("11111111111"))
	})
	err = http3.ListenAndServe("0.0.0.0:5321", certPem, keyPem, serveMux)
	if err != nil {
		log.Println(err)
		return
	}
}
