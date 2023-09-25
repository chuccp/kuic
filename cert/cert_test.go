package cert

import (
	"testing"
)

func TestCrt(t *testing.T) {

	err := CreateCa("ca.key", "ca.crt")
	if err != nil {
		t.Log(err)
		return
	}

	certificate, err := ReadCertificateForPem("ca.crt")
	if err != nil {
		t.Log(err)
		return
	}

	key, err2 := ReadRsaPrivateKeyForPem("ca.key")
	if err2 != nil {
		return
	}

	var parent = &Cert{
		CSR:     certificate,
		CertKey: key,
	}

	err = CreateCert("client.key", "client.pem", parent)
	if err != nil {
		t.Log(err)
		return
	}
	err = CreateCert("server.key", "server.pem", parent)
	if err != nil {
		t.Log(err)
		return
	}

}
