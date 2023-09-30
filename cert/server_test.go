package cert

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"testing"
)

func TestName(t *testing.T) {

	caCert, err := ReadCertificateForPem("client.cer")
	if err != nil {
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	serve := http.NewServeMux()
	serve.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("1111111"))

		log.Println(request.TLS)

	})
	s := &http.Server{
		Addr:    ":2356",
		Handler: serve,
		TLSConfig: &tls.Config{
			//RootCAs:    caCertPool,
			ClientCAs:  caCertPool,
			ClientAuth: tls.VerifyClientCertIfGiven,
		},
	}
	err = s.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		log.Println(err)
		return
	}

}
