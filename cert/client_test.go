package cert

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"testing"
)

func TestClient(t *testing.T) {

	caCert, err := ReadCertificateForPem("ca.crt")
	if err != nil {
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	cert, err := tls.LoadX509KeyPair("client.pem", "client.key")
	if err != nil {
		t.Error(err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "localhost",
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport}
	get, err := httpClient.Get("https://127.0.0.1:2356/")
	if err != nil {
		t.Error(err)
		return
	}
	all, err := io.ReadAll(get.Body)
	if err != nil {
		return
	}
	t.Log(string(all))
}
