package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path"
)

type Certificate struct {
	cert *tls.Certificate
	ca   *x509.Certificate
}

type Manager struct {
	certPath      string
	serverName    string
	serverCaPem   []byte
	serverCertPem []byte
	serverKeyPEM  []byte
	cert          *tls.Certificate
	certPool      *x509.CertPool
}

func NewManager(certPath string, serverName string) *Manager {
	return &Manager{certPath: certPath, serverName: serverName}
}
func (m *Manager) Init() (err error) {
	serverPath := path.Join(m.certPath, "server.cert")
	m.serverCaPem, m.serverCertPem, m.serverKeyPEM, err = CreateOrReadKuicServerCertPem(m.serverName, serverPath)
	if err != nil {
		return
	}
	cert, err := tls.X509KeyPair(m.serverCertPem, m.serverKeyPEM)
	if err != nil {
		return
	}
	m.cert = &cert
	m.certPool = x509.NewCertPool()
	return
}
func (m *Manager) GetServerCertificate() *tls.Certificate {
	return m.cert
}
func (m *Manager) GetCertPool() *x509.CertPool {
	return m.certPool
}
func (m *Manager) CreateClientCert(username string) (*Certificate, error) {
	clientCertPath := path.Join(m.certPath, username+".client.cert")
	clientCaPath := path.Join(m.certPath, username+".client.ca")
	clientCaPem, clientCertPem, clientKeyPEM, err := CreateOrReadKuicClientCert(m.serverName, m.serverCaPem, clientCertPath, clientCaPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(clientCertPem, clientKeyPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(clientCaPem)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: &cert, ca: ca}, nil
}
