package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/chuccp/kuic/util"
	"math/big"
	"time"
)

func CreateCert(keyPath string, certPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(time.Now().Unix())}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	err = util.WriteFile(keyPath, keyPEM)
	if err != nil {
		return err
	}
	return util.WriteFile(certPath, certPEM)

}

func CreateOrReadCert(keyPath string, certPath string) error {
	hasKey, err := util.ExistsFile(keyPath)
	if err != nil {
		return err
	}
	hasCert, err := util.ExistsFile(certPath)
	if err != nil {
		return err
	}
	if hasKey && hasCert {
		return nil
	}
	return CreateCert(keyPath, certPath)

}
