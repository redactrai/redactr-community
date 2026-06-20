package catrust

import (
	"path/filepath"
	"testing"

	"github.com/redactrai/redactr-community/internal/certgen"
)

func TestCommonName(t *testing.T) {
	d := t.TempDir()
	cert := filepath.Join(d, "ca.pem")
	key := filepath.Join(d, "ca.key")
	if _, err := certgen.LoadOrCreateCA(cert, key); err != nil {
		t.Fatal(err)
	}
	cn, err := commonName(cert)
	if err != nil {
		t.Fatal(err)
	}
	if cn == "" {
		t.Fatal("expected non-empty CommonName")
	}
	const wantCN = "Redactr CA"
	if cn != wantCN {
		t.Fatalf("expected CommonName %q, got %q", wantCN, cn)
	}
}
