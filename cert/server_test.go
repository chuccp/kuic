package cert

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"testing"
)

func TestName(t *testing.T) {

	caCert, err := ReadCertificateForPem("ca.crt")
	if err != nil {
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	serve := http.NewServeMux()
	serve.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("1111111"))
	})
	s := &http.Server{
		Addr:    ":2356",
		Handler: serve,
		TLSConfig: &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}
	err = s.ListenAndServeTLS("server.pem", "server.key")
	if err != nil {
		log.Println(err)
		return
	}

}
