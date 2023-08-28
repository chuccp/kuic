package http

import (
	"net/http"
	"testing"
)

func TestServer(t *testing.T) {

	keyPem := "key2.PEM"
	certPem := "cert2.PEM"
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("11111111111"))
	})
	err := ListenAndServe("0.0.0.0:6321", certPem, keyPem, serveMux)
	if err != nil {
		return
	}

}
