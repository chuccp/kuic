package cert

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/chuccp/kuic/util"
	"testing"
)

func TestCrt(t *testing.T) {

	err := CreateCertGroup(nil, "server.cer", "server.crt", "server.key")
	if err != nil {
		return
	}
	err = CreateCertGroup(nil, "client.cer", "client.crt", "client.key")
	if err != nil {
		return
	}
	t.Log(err)

	//func CreateKuicCert(subject *pkix.Name, caPath, certPath string) error {
	//
	//	return nil
	//
	//}

}

func TestQuic(t *testing.T) {

	err := CreateKuicCert("server_kuic.cer", "client_kuic.cer")
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
