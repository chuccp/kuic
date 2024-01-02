package http

import (
	"github.com/chuccp/kuic/cert"
	"github.com/chuccp/kuic/testdata"
	"net/http"
	"testing"
	"time"
)

func TestServer(t *testing.T) {

	server, err := CreateServer("192.168.1.123:5565")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := "keyPath.PEM"
	certPath := "certPath.PEM"
	err = cert.CreateOrReadCert(keyPath, certPath)
	if err != nil {
		t.Fatal(err)
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("11111111111"))
	})

	go func() {

		for {
			time.Sleep(2 * time.Second)
			get, err := server.GetHttpClient(StrToAddress("192.168.1.123:5565"))
			if err != nil {
				t.Fatal(err)
			}

			all, err := get.Get("/")
			if err != nil {
				t.Fatal(err)
			}
			t.Log(all)
		}

	}()

	fullpem, privkey := testdata.GetCertificatePaths()
	err = server.ListenAndServe(fullpem, privkey, serveMux)
	if err != nil {
		t.Fatal(err)
	}

}
