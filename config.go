package certigo

import "crypto/tls"

func GetAdvanceTlsConfig(GetCertificateFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetCertificate: GetCertificateFunc,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			// Use strong cipher suites only
			//TLS 1.2
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			//tls 1.3
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			//not use CHACHA20 because servers not have hardware acceleration
		},
		PreferServerCipherSuites: true, // Prefer the server's cipher suite over client's preference

	}
}

func GetTlsConfig(GetCertificateFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetCertificate: GetCertificateFunc,
		MinVersion:     tls.VersionTLS12,
	}
}
