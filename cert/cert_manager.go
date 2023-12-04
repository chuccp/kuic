package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/chuccp/kuic/util"
	"path"
)

type Certificate struct {
	Cert       *tls.Certificate
	CaPem      []byte
	ServerName string
	UserName   string
}

type Manager struct {
	certPath         string
	serverName       string
	serverCaPem      []byte
	serverCaKeyPem   []byte
	clientCaPem      []byte
	clientCaKeyPem   []byte
	serverCertPem    []byte
	serverCertKeyPEM []byte
	cert             *tls.Certificate
	certPool         *x509.CertPool
}

func NewManager(certPath string) *Manager {
	return &Manager{certPath: certPath}
}
func (m *Manager) Init() (err error) {
	m.serverCaPem, m.serverCaKeyPem, err = CreateOrReadCaPem(path.Join(m.certPath, "server.ca"))
	if err != nil {
		return err
	}
	serverCa, _ := pem.Decode(m.serverCaPem)
	var ca *x509.Certificate
	ca, err = x509.ParseCertificate(serverCa.Bytes)
	if err != nil {
		return
	}
	m.serverName = util.ServerName(ca.Raw)
	m.serverCertPem, m.serverCertKeyPEM, err = CreateOrReadCertPem(m.serverName, "kuic", m.serverCaPem, m.serverCaKeyPem, path.Join(m.certPath, "server.cert"))
	cert, err := tls.X509KeyPair(m.serverCertPem, m.serverCertKeyPEM)
	if err != nil {
		return
	}
	m.cert = &cert
	m.certPool = x509.NewCertPool()
	m.clientCaPem, m.clientCaKeyPem, err = CreateOrReadCaPem(path.Join(m.certPath, "client.ca"))
	m.certPool.AppendCertsFromPEM(m.clientCaPem)
	return
}
func (m *Manager) GetServerCertificate() *tls.Certificate {
	return m.cert
}
func (m *Manager) GetServerName() string {
	return m.serverName
}
func (m *Manager) GetCertPool() *x509.CertPool {
	return m.certPool
}
func (m *Manager) CreateClientCert(username string) (*Certificate, error) {
	clientCertPath := path.Join(m.certPath, username+".client.cert")
	clientCertPem, clientKeyPEM, err := CreateOrReadCertPem(m.serverName, username, m.clientCaPem, m.clientCaKeyPem, clientCertPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(clientCertPem, clientKeyPEM)
	if err != nil {
		return nil, err
	}

	certificate := &Certificate{Cert: &cert, CaPem: m.serverCaPem, ServerName: m.serverName, UserName: username}
	return certificate, nil
}

func (m *Manager) CreateOrReadClientKuicCertFile(username string) (string, *Certificate, error) {
	clientCertPath := path.Join(m.certPath, username+".client.cert")
	clientCertPem, clientKeyPEM, err := CreateOrReadCertPem(m.serverName, username, m.clientCaPem, m.clientCaKeyPem, clientCertPath)
	if err != nil {
		return "", nil, err
	}
	kuicCertPath := path.Join(m.certPath, username+".kuic.cert")
	flag := util.ExistsFile(kuicCertPath)
	if flag {
		return kuicCertPath, nil, err
	}
	err = util.WriteBytesFile(kuicCertPath, m.serverCaPem, clientCertPem, clientKeyPEM)
	if err != nil {
		return "", nil, err
	}
	cert, err := tls.X509KeyPair(clientCertPem, clientKeyPEM)
	if err != nil {
		return "", nil, err
	}
	certificate := &Certificate{Cert: &cert, CaPem: m.serverCaPem, ServerName: m.serverName, UserName: username}
	return kuicCertPath, certificate, nil
}

func ParseClientKuicCertFile(certPath string) (string, *Certificate, error) {
	var data []byte
	data, err := util.ReadFile(certPath)
	if err != nil {
		return "", nil, err
	}
	certificate, err := ParseClientKuicCertBytes(data)
	if err != nil {
		return "", nil, err
	}
	return certPath, certificate, nil
}
func ParseClientKuicCertBytes(data []byte) (*Certificate, error) {
	serverCaBlock, rest := pem.Decode(data)
	certBlock, rest := pem.Decode(rest)
	keyBlock, _ := pem.Decode(rest)
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(certBlock), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, err
	}
	ce, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	serverName := ce.DNSNames[0]
	username := string(ce.SubjectKeyId)
	certificate := &Certificate{Cert: &cert, CaPem: pem.EncodeToMemory(serverCaBlock), ServerName: serverName, UserName: username}
	return certificate, nil
}
