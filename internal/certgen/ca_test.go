package certgen

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateAndIssue(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	ca, err := LoadOrCreateCA(cert, key)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if ca.Cert == nil || ca.Key == nil {
		t.Fatal("CA not populated")
	}
	// IssueCert returns tls.Certificate (value), not a pointer; check the leaf is valid
	// by verifying its Certificate chain is populated.
	leaf, err := ca.IssueCert("api.anthropic.com")
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if leaf.Certificate == nil {
		t.Fatal("nil leaf cert")
	}
	ca2, err := LoadOrCreateCA(cert, key)
	if err != nil || !ca2.Cert.Equal(ca.Cert) {
		t.Fatalf("expected idempotent load, err=%v", err)
	}
}
