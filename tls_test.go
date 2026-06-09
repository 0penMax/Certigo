package certigo

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

func TestFindCertificate_ExactMatch(t *testing.T) {
	exactCert := &tls.Certificate{}

	s := &Storage{
		certs: map[string]*tls.Certificate{
			"example.com": exactCert,
		},
	}

	got := s.findCertificate("example.com")

	if got != exactCert {
		t.Fatalf("expected exact certificate, got %#v", got)
	}
}

func TestFindCertificate_WildcardMatch(t *testing.T) {
	wildcardCert := &tls.Certificate{}

	s := &Storage{
		certs: map[string]*tls.Certificate{
			"*.example.com": wildcardCert,
		},
	}

	got := s.findCertificate("api.example.com")

	if got != wildcardCert {
		t.Fatalf("expected wildcard certificate, got %#v", got)
	}
}

func TestFindCertificate_PrefersExactOverWildcard(t *testing.T) {
	exactCert := &tls.Certificate{}
	wildcardCert := &tls.Certificate{}

	s := &Storage{
		certs: map[string]*tls.Certificate{
			"api.example.com": exactCert,
			"*.example.com":   wildcardCert,
		},
	}

	got := s.findCertificate("api.example.com")

	if got != exactCert {
		t.Fatal("expected exact certificate to be preferred")
	}
}

func TestFindCertificate_MultiLevelWildcardMatch(t *testing.T) {
	wildcardCert := &tls.Certificate{}

	s := &Storage{
		certs: map[string]*tls.Certificate{
			"*.example.com": wildcardCert,
		},
	}

	got := s.findCertificate("foo.bar.example.com")

	if got != wildcardCert {
		t.Fatal("expected wildcard certificate")
	}
}

func TestFindCertificate_NotFound(t *testing.T) {
	s := &Storage{
		certs: map[string]*tls.Certificate{
			"*.example.com": &tls.Certificate{},
		},
	}

	got := s.findCertificate("example.org")

	if got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
}

func TestFindCertificate_ExactPreferredOverWildcard(t *testing.T) {
	exact := &tls.Certificate{}
	wildcard := &tls.Certificate{}

	s := &Storage{
		certs: map[string]*tls.Certificate{
			"api.example.com": exact,
			"*.example.com":   wildcard,
		},
	}

	got := s.findCertificate("api.example.com")

	if got != exact {
		t.Fatal("expected exact match to be preferred")
	}
}

func TestGetCertificateFunc_NoServerName(t *testing.T) {
	s := &Storage{}

	_, err := s.GetCertificateFunc(&tls.ClientHelloInfo{})

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "no server name indicated") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetCertificateFunc_Found(t *testing.T) {
	cert := &tls.Certificate{}

	s := &Storage{
		certs: map[string]*tls.Certificate{
			"example.com": cert,
		},
	}

	got, err := s.GetCertificateFunc(&tls.ClientHelloInfo{
		ServerName: "example.com",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != cert {
		t.Fatal("returned wrong certificate")
	}
}

func TestGetCertificateFunc_NotFound(t *testing.T) {
	s := &Storage{
		certs: map[string]*tls.Certificate{},
	}

	_, err := s.GetCertificateFunc(&tls.ClientHelloInfo{
		ServerName: "example.com",
	})

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "certificate not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetDomains_UsesSAN(t *testing.T) {
	cert := &tls.Certificate{
		Leaf: &x509.Certificate{
			DNSNames: []string{
				"example.com",
				"www.example.com",
			},
			Subject: pkix.Name{
				CommonName: "old-cn.example.com",
			},
		},
	}

	got, err := getDomains(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{
		"example.com",
		"www.example.com",
	}

	if len(got) != len(want) {
		t.Fatalf("expected %v got %v", want, got)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v got %v", want, got)
		}
	}
}

func TestGetDomains_NoDomains(t *testing.T) {
	cert := &tls.Certificate{
		Leaf: &x509.Certificate{},
	}

	_, err := getDomains(cert)

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "contains no DNS names") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetDomains_EmptyChain(t *testing.T) {
	cert := &tls.Certificate{}

	_, err := getDomains(cert)

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "certificate chain is empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetDomains_InvalidCertificate(t *testing.T) {
	cert := &tls.Certificate{
		Certificate: [][]byte{
			[]byte("not-a-certificate"),
		},
	}

	_, err := getDomains(cert)

	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "failed to parse certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}
