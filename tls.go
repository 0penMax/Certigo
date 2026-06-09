package certigo

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
)

type Storage struct {
	mutex         sync.RWMutex
	certs         map[string]*tls.Certificate
	certsDiscInfo []CertSource
}

type CertSource struct {
	PublicKeyPath  string
	PrivateKeyPath string
}

// GetCertificateFunc is used to either retrieve or load and cache the certificate.
func (s *Storage) GetCertificateFunc(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Determine the domain from the ClientHello (SNI).
	domain := clientHello.ServerName
	if domain == "" {
		return nil, fmt.Errorf("no server name indicated")
	}

	// First, try to read the certificate from the cache under a read lock.
	s.mutex.RLock()
	cert, exists := s.certs[domain]
	s.mutex.RUnlock()
	if exists {
		return cert, nil
	}

	return nil, fmt.Errorf("error cert for %s not find", domain)
}

func (s *Storage) loadCerts() error {
	certs := make(map[string]*tls.Certificate)
	for _, path := range s.certsDiscInfo {
		loadedCert, err := tls.LoadX509KeyPair(path.PublicKeyPath, path.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("error loading cert %s or %s: %w", path.PublicKeyPath, path.PrivateKeyPath, err)
		}

		domains, err := getDomains(loadedCert)
		if err != nil {
			return fmt.Errorf("error read domains from certs for %s: %w", path.PublicKeyPath, err)
		}

		for _, d := range domains {
			certs[d] = &loadedCert
		}
	}
	s.mutex.Lock()
	s.certs = certs
	s.mutex.Unlock()
	return nil
}

func (s *Storage) ReloadCerts() error {
	return s.loadCerts()
}

func (s *Storage) Init(diskInfo []CertSource) error {
	s.mutex.Lock()
	s.certsDiscInfo = diskInfo
	s.mutex.Unlock()
	return s.loadCerts()
}

// getDomains returns the domain names found in the given tls.Certificate.
func getDomains(cert tls.Certificate) ([]string, error) {
	// Parse the first certificate if cert.Leaf is nil.
	var xcert *x509.Certificate
	if cert.Leaf != nil {
		xcert = cert.Leaf
	} else {
		if len(cert.Certificate) == 0 {
			return nil, errors.New("certificate chain is empty")
		}
		var err error
		xcert, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
	}

	// Collect domain names.
	var domains []string

	// The Common Name is historically where the primary domain is stored.
	if xcert.Subject.CommonName != "" {
		domains = append(domains, xcert.Subject.CommonName)
	}

	// Additionally, the SANs (DNSNames) field might contain extra domains.
	domains = append(domains, xcert.DNSNames...)

	return domains, nil
}
