package http

import (
	"github.com/chuccp/kuic/testdata"
	"net/http"
	"testing"
)

func TestReverseProxyServer(t *testing.T) {

	ser, err := CreateServer("0.0.0.0:5252")
	if err != nil {
		return
	}

	cert, priv := testdata.GetCertificatePaths()

	serveMux := http.NewServeMux()

	proxy, err := ser.GetReverseProxy("127.0.0.1:2156")
	if err != nil {
		return
	}
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		proxy.ServeHTTP(writer, request)
	})
	err = ser.ListenAndServe(cert, priv, serveMux)
	if err != nil {
		return
	}

}
