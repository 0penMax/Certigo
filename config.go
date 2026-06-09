package certigo

import "crypto/tls"

// GetAdvanceTlsConfig returns a hardened tls.Config with an explicit TLS 1.2
// cipher list (AES-GCM only;)and TLS 1.3 support via Go's built-in stack.
// Note: CipherSuites only affects TLS 1.2 negotiation. TLS 1.3 ciphers are
// selected automatically by Go and cannot be overridden.
func GetAdvanceTlsConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.2 — ECDHE + AES-GCM only
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// GetTlsConfig returns a minimal tls.Config using Go's default cipher selection.
func GetTlsConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}
