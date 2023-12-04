package http

import (
	"github.com/chuccp/kuic/cert"
	"log"
	"net/http"
	"testing"
	"time"
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

	manager := cert.NewManager("server")
	err = manager.Init()
	if err != nil {
		t.Log(err)
		return
	}

	go func() {
		time.Sleep(time.Second * 3)
		clientCert, err := manager.CreateClientCert("abc")
		log.Println(err)

		file, _, err := manager.CreateOrReadClientKuicCertFile("aaa")
		if err != nil {
			return
		}
		log.Println(file)
		client, err := server.GetTlsHttpClient("127.0.0.1:2563", clientCert)

		log.Println("======000=======", client, err)
		if err != nil {
			return
		}
		response, err := client.GetResponse("/")
		log.Println("======111=======", response, err)

		if err != nil {
			log.Println("======111=======", response, err)
			return
		}

		log.Println("======close=======")
		client.Close()
		log.Println("======!!!!=======")
	}()

	log.Println("===============")
	err = server.ListenAndServeWithKuicTls(manager, serveMux)
	if err != nil {
		t.Log(err)
		return
	}

}
