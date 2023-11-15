package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/chuccp/kuic/util"
	"path"
	"strings"
)

type Certificate struct {
	Cert           *tls.Certificate
	ClientCa       *x509.Certificate
	ServerCa       *x509.Certificate
	ClientCertPath string
	ClientCaPath   string
	ServerName     string
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

func NewManager(certPath string) *Manager {
	return &Manager{certPath: certPath}
}
func (m *Manager) Init() (err error) {
	serverPath := path.Join(m.certPath, "server.cert")
	m.serverName, m.serverCaPem, m.serverCertPem, m.serverKeyPEM, err = CreateOrReadKuicServerCertPem(serverPath)
	if err != nil {
		return
	}
	cert, err := tls.X509KeyPair(m.serverCertPem, m.serverKeyPEM)
	if err != nil {
		return
	}
	m.cert = &cert
	m.certPool = x509.NewCertPool()
	m.loadClientCa()
	return
}
func (m *Manager) loadClientCa() {
	file, err := util.NewFile(m.certPath)
	if err != nil {
		return
	}
	defer file.Close()
	if file.IsDir() {
		list, err := file.List()
		if err != nil {
			return
		}
		if len(list) > 0 {
			for _, ele := range list {
				if !ele.IsDir() {
					if strings.HasSuffix(ele.Name(), ".ca") {
						data, err := ele.ReadAll()
						if err != nil {
							return
						}
						block, _ := pem.Decode(data)
						sca, err := x509.ParseCertificate(block.Bytes)
						m.certPool.AddCert(sca)
						ele.Close()
					}
				}

			}

		}
	}

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
	caBlock, _ := pem.Decode(m.serverCaPem)
	sca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}
	m.certPool.AddCert(ca)
	return &Certificate{ServerName: m.serverName, Cert: &cert, ClientCa: ca, ServerCa: sca, ClientCertPath: clientCertPath, ClientCaPath: clientCaPath}, nil
}
