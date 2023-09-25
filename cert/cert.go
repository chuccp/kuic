package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/chuccp/kuic/util"
	"math/big"
	"time"
)

type Cert struct {
	CSR     *x509.Certificate
	CertKey *rsa.PrivateKey
	CERT    []byte
}

func generateCert(subject *pkix.Name, parent *Cert, bits int, isCA bool) (cert *Cert, err error) {
	cert = &Cert{}
	cert.CertKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	cert.CSR = &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		IsCA:         isCA,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(100, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if isCA {
		cert.CSR.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		cert.CSR.BasicConstraintsValid = true
	} else {
		cert.CSR.KeyUsage = x509.KeyUsageDigitalSignature
		cert.CSR.SubjectKeyId = []byte("abc")
		cert.CSR.DNSNames = []string{"localhost"}
		//cert.CSR.ExcludedIPRanges
	}
	if subject != nil {
		cert.CSR.Subject = *subject
	} else {
		if parent == nil {
			cert.CSR.Subject = pkix.Name{
				Country:            []string{"Earth"},
				Organization:       []string{"Kuic"},
				OrganizationalUnit: []string{"Freedom"},
				CommonName:         "share",
			}
		} else {
			cert.CSR.Subject = pkix.Name{
				Country:            []string{"Earth-0"},
				Organization:       []string{"Kuic-0"},
				OrganizationalUnit: []string{"Freedom-0"},
				CommonName:         "share-0",
			}
		}

		//Country : []string{"Earth"},
		//                        Organization: []string{"Mother Nature"},
	}
	var parentCsr *x509.Certificate

	caPrivateKey := cert.CertKey
	if parent == nil {
		parentCsr = cert.CSR
	} else {
		caPrivateKey = parent.CertKey
		parentCsr = parent.CSR
	}
	cert.CERT, err = x509.CreateCertificate(rand.Reader, cert.CSR, parentCsr, &cert.CertKey.PublicKey, caPrivateKey)
	if err != nil {
		return
	}
	return
}

func CreateCa(keyPath string, certPath string) error {
	return CreateCertAndSubject(keyPath, certPath, nil)
}
func CreateCert(keyPath string, certPath string, parent *Cert) error {
	if parent != nil {
		parent.CSR.PublicKey = nil
	}
	cert, err := generateCert(nil, parent, 4096, false)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.CertKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CERT})
	err = util.WriteFile(keyPath, keyPEM)
	if err != nil {
		return err
	}
	return util.WriteFile(certPath, certPEM)
}
func CreateCertAndSubject(keyPath string, certPath string, subject *pkix.Name) error {
	cert, err := generateCert(subject, nil, 4096, true)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.CertKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CERT})
	err = util.WriteFile(keyPath, keyPEM)
	if err != nil {
		return err
	}
	return util.WriteFile(certPath, certPEM)
}

func ReadCertificateForPem(certPath string) (*x509.Certificate, error) {
	file, err := util.NewFile(certPath)
	if err != nil {
		return nil, err
	}
	data, err := file.ReadAll()
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(data)
	return x509.ParseCertificate(p.Bytes)
}
func ReadRsaPrivateKeyForPem(keyPath string) (*rsa.PrivateKey, error) {
	file, err := util.NewFile(keyPath)
	if err != nil {
		return nil, err
	}
	data, err := file.ReadAll()
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(data)
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

// Subject                     pkix.Name

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
	return CreateCa(keyPath, certPath)
}
