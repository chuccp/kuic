package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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

	return generateCertForDNSNames(subject, parent, []string{"localhost"}, bits, isCA)
}

func generateCa(subject *pkix.Name, bits int) (cert *Cert, err error) {
	return generateCertForDNSNames(subject, nil, []string{}, bits, true)
}

func generateCertForDNSNames(subject *pkix.Name, parent *Cert, DNSNames []string, bits int, isCA bool) (cert *Cert, err error) {
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
		cert.CSR.DNSNames = DNSNames
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

func CreateCertGroup(subject *pkix.Name, caPath, certPath, keyPath string) error {
	CA, err := generateCert(subject, nil, 4096, true)
	if err != nil {
		return err
	}
	cert, err := generateCert(subject, CA, 4096, false)
	if err != nil {
		return err
	}
	caPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: CA.CERT})
	err = util.WriteFile(caPath, caPem)
	if err != nil {
		return err
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CERT})
	err = util.WriteFile(certPath, certPem)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.CertKey)})
	return util.WriteFile(keyPath, keyPEM)
}

func createCaAndCert() (CA *Cert, cert *Cert, err error) {
	subject := &pkix.Name{
		Country:            []string{"Earth"},
		Organization:       []string{"Kuic"},
		OrganizationalUnit: []string{"Freedom"},
		CommonName:         "share",
	}
	CA, err = generateCa(subject, 4096)
	if err != nil {
		return
	}
	subject = &pkix.Name{
		Country:            []string{"Earth-0"},
		Organization:       []string{"Kuic-0"},
		OrganizationalUnit: []string{"Freedom-0"},
		CommonName:         "share-0",
	}
	serverName := util.ServerName(CA.CERT)
	cert, err = generateCertForDNSNames(subject, CA, []string{serverName}, 4096, false)
	if err != nil {
		return
	}
	return
}
func createCa() (CA *Cert, err error) {
	subject := &pkix.Name{
		Country:            []string{"Earth"},
		Organization:       []string{"Kuic"},
		OrganizationalUnit: []string{"Freedom"},
		CommonName:         "share",
	}
	CA, err = generateCa(subject, 4096)
	if err != nil {
		return
	}
	return
}
func createClientCaAndCert(serverName string) (CA *Cert, cert *Cert, err error) {
	subject := &pkix.Name{
		Country:            []string{"Earth"},
		Organization:       []string{"Kuic"},
		OrganizationalUnit: []string{"Freedom"},
		CommonName:         "share",
	}
	CA, err = generateCa(subject, 4096)
	if err != nil {
		return
	}
	subject = &pkix.Name{
		Country:            []string{"Earth-0"},
		Organization:       []string{"Kuic-0"},
		OrganizationalUnit: []string{"Freedom-0"},
		CommonName:         "share-0",
	}
	cert, err = generateCertForDNSNames(subject, CA, []string{serverName}, 4096, false)
	if err != nil {
		return
	}
	return
}

func CreateKuicCert(serverPath string, clientPath string) (err error) {
	serverCa, serverCert, err := createCaAndCert()
	if err != nil {
		return err
	}
	clientCa, clientCert, err := createCaAndCert()
	if err != nil {
		return err
	}
	clientCaPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCa.CERT})
	serverCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.CERT})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverCert.CertKey)})
	err = util.WriteBytesFile(serverPath, clientCaPem, serverCertPem, serverKeyPEM)
	if err != nil {
		return err
	}
	serverCaPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCa.CERT})
	clientCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.CERT})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientCert.CertKey)})
	err = util.WriteBytesFile(clientPath, serverCaPem, clientCertPem, clientKeyPEM)
	if err != nil {
		return err
	}
	return
}

func CreateKuicServerCert(serverPath string) (err error) {
	serverCa, serverCert, err := createCaAndCert()
	if err != nil {
		return err
	}
	clientCaPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCa.CERT})
	serverCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.CERT})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverCert.CertKey)})
	err = util.WriteBytesFile(serverPath, clientCaPem, serverCertPem, serverKeyPEM)
	if err != nil {
		return err
	}
	return
}

func CreateOrReadCaPem(savePath string) (caPem []byte, keyPem []byte, err error) {
	flag := util.ExistsFile(savePath)
	if flag {
		var data []byte
		data, err = util.ReadFile(savePath)

		cert, rest := pem.Decode(data)
		key, _ := pem.Decode(rest)
		_, err = x509.ParseCertificate(cert.Bytes)
		if err != nil {
			return nil, nil, err
		}
		_, err = x509.ParsePKCS1PrivateKey(key.Bytes)
		if err != nil {
			return nil, nil, err
		}
		caPem = pem.EncodeToMemory(cert)
		keyPem = pem.EncodeToMemory(key)
		return
	}
	subject := &pkix.Name{
		Country:            []string{"Earth"},
		Organization:       []string{"Kuic"},
		OrganizationalUnit: []string{"Freedom"},
		CommonName:         "share",
	}
	cert, err := generateCa(subject, 4096)

	caPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CERT})
	keyPem = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.CertKey)})
	err = util.WriteBytesFile(savePath, caPem, keyPem)
	if err != nil {
		return
	}
	return
}

func CreateOrReadCertPem(serverName string, caPem []byte, keyPem []byte, certPath string) (certPem []byte, keyPEM []byte, err error) {
	flag := util.ExistsFile(certPath)
	if flag {
		var data []byte
		data, err = util.ReadFile(certPath)

		cert, rest := pem.Decode(data)
		key, _ := pem.Decode(rest)
		_, err = x509.ParseCertificate(cert.Bytes)
		if err != nil {
			return nil, nil, err
		}
		_, err = x509.ParsePKCS1PrivateKey(key.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certPem = pem.EncodeToMemory(cert)
		keyPEM = pem.EncodeToMemory(key)
		return
	}

	CA := &Cert{}
	caBlock, _ := pem.Decode(caPem)
	CA.CSR, err = x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(keyPem)
	CA.CertKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	subject := &pkix.Name{
		Country:            []string{"Earth-0"},
		Organization:       []string{"Kuic-0"},
		OrganizationalUnit: []string{"Freedom-0"},
		CommonName:         "share-0",
	}
	cert, err := generateCertForDNSNames(subject, CA, []string{serverName}, 4096, false)
	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CERT})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.CertKey)})
	err = util.WriteBytesFile(certPath, certPem, keyPEM)
	if err != nil {
		return
	}
	return

}

func CreateOrReadKuicServerCertPem(serverPath string) (serverName string, serverCaPem []byte, serverCertPem []byte, serverKeyPEM []byte, err error) {
	flag := util.ExistsFile(serverPath)
	if flag {
		var data []byte
		data, err = util.ReadFile(serverPath)
		if err != nil {
			return "", nil, nil, nil, err
		}
		ca, rest := pem.Decode(data)
		cert, rest := pem.Decode(rest)
		var certificate *x509.Certificate
		certificate, err = x509.ParseCertificate(cert.Bytes)
		if err != nil {
			return "", nil, nil, nil, err
		}
		serverName = certificate.DNSNames[0]
		key, _ := pem.Decode(rest)
		serverCaPem = pem.EncodeToMemory(ca)
		serverCertPem = pem.EncodeToMemory(cert)
		serverKeyPEM = pem.EncodeToMemory(key)
		return
	}

	serverCa, serverCert, err := createCaAndCert()
	if err != nil {
		return "", nil, nil, nil, err
	}
	serverCaPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCa.CERT})
	serverCertPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.CERT})
	serverKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverCert.CertKey)})
	err = util.WriteBytesFile(serverPath, serverCaPem, serverCertPem, serverKeyPEM)
	if err != nil {
		return "", nil, nil, nil, err
	}
	return
}
func CreateOrReadKuicClientCert(serverCaPem []byte, clientCertPath string, clientCaPath string) (clientCaPem []byte, clientCertPem []byte, clientKeyPEM []byte, err error) {
	flag0 := util.ExistsFile(clientCertPath)
	flag1 := util.ExistsFile(clientCaPath)
	if flag0 && flag1 {
		var data []byte
		data, err = util.ReadFile(clientCertPath)
		if err != nil {
			return nil, nil, nil, err
		}
		var caData []byte
		caData, err = util.ReadFile(clientCaPath)
		if err != nil {
			return nil, nil, nil, err
		}
		ca, rest := pem.Decode(data)
		cert, rest := pem.Decode(rest)
		key, rest := pem.Decode(rest)
		sCaPem := pem.EncodeToMemory(ca)
		if bytes.Compare(sCaPem, serverCaPem) == 0 {
			caBlock, _ := pem.Decode(caData)
			clientCaPem = pem.EncodeToMemory(caBlock)
			clientCertPem = pem.EncodeToMemory(cert)
			clientKeyPEM = pem.EncodeToMemory(key)
			return
		}

	}

	serverCa, _ := pem.Decode(serverCaPem)
	var ca *x509.Certificate
	ca, err = x509.ParseCertificate(serverCa.Bytes)
	if err != nil {
		return
	}
	serverName := util.ServerName(ca.Raw)
	clientCa, clientCert, err := createClientCaAndCert(serverName)
	clientCaPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCa.CERT})
	clientCertPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.CERT})
	clientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientCert.CertKey)})
	err = util.WriteBytesFile(clientCertPath, serverCaPem, clientCertPem, clientKeyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	err = util.WriteBytesFile(clientCaPath, clientCaPem)
	if err != nil {
		return nil, nil, nil, err
	}
	return
}

func ReadKuicCert(certPath string) (ca *x509.Certificate, cert *tls.Certificate, certificate *x509.Certificate, err error) {

	data, err := util.ReadFile(certPath)
	if err != nil {
		return
	}
	caBlock, rest := pem.Decode(data)
	ca, err = x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return
	}
	certPEMBlock, rest := pem.Decode(rest)
	xca, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		return
	}
	keyPEMBlock, rest := pem.Decode(rest)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(certPEMBlock), pem.EncodeToMemory(keyPEMBlock))
	if err != nil {
		return
	}
	return ca, &pair, xca, err
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
	hasKey := util.ExistsFile(keyPath)

	hasCert := util.ExistsFile(certPath)

	if hasKey && hasCert {
		return nil
	}
	return CreateCa(keyPath, certPath)
}
