package certigo

import (
	"crypto/tls"
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
