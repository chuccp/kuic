package http

import (
	"github.com/chuccp/kuic/cert"
	"log"
	"net/http"
	"testing"
)

func TestServerAAA(t *testing.T) {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("11111111111"))
	})

	server, err := CreateServer("0.0.0.0:2563")
	if err != nil {
		return
	}

	manager := cert.NewManager("server", "olnfhscjh")
	err = manager.Init()
	if err != nil {
		t.Log(err)
		return
	}
	log.Println("===============")
	err = server.ListenAndServeWithKuicTls(manager, serveMux)
	if err != nil {
		t.Log(err)
		return
	}
}
