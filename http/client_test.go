package http

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/chuccp/kuic/cert"
	"github.com/chuccp/kuic/util"
	"testing"
)

func TestQuic(t *testing.T) {

	err := cert.CreateKuicCert("xxxxxxxxxx", "server_kuic.cer", "client_kuic.cer")
	if err != nil {
		return
	}

}
func TestReadQuic(t *testing.T) {

	data, err := util.ReadFile("server_kuic.cer")
	if err != nil {
		return
	}

	ca, rest := pem.Decode(data)

	certPEMBlock, rest := pem.Decode(rest)

	keyPEMBlock, rest := pem.Decode(rest)

	certificate, err := x509.ParseCertificate(ca.Bytes)

	t.Log("!!!!!!!======0", certificate, err)

	x509Cert, err := x509.ParseCertificate(certPEMBlock.Bytes)

	t.Log("!!!!!!!======1", x509Cert.DNSNames, x509Cert, err)

	key, err := x509.ParsePKCS1PrivateKey(keyPEMBlock.Bytes)

	t.Log("!!!!!!!======2", key, err)

}
