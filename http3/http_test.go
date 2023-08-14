package http

import (
	"github.com/chuccp/kuic/cert"
	"log"
	"net/http"
	"testing"
	"time"
)

func TestServer(t *testing.T) {

	keyPem := "key2.PEM"
	certPem := "cert2.PEM"
	server, err := createServer("0.0.0.0:2153")
	if err != nil {
		return
	}
	err = cert.CreateOrReadCert(keyPem, certPem)
	if err != nil {
		log.Println(err)
		return
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("11111111111"))
	})

	go func() {
		err = server.Listen(certPem, keyPem, serveMux)
		if err != nil {
			log.Println(err)
			return
		}
	}()

	time.Sleep(time.Second * 10)
}
