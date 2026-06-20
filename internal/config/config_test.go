package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	old := filepath.Join(home, ".redactr-community")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "ca.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	Migrate()
	if _, err := os.Stat(filepath.Join(home, ".redactr", "ca.pem")); err != nil {
		t.Fatalf("expected migrated file at ~/.redactr/ca.pem: %v", err)
	}
}
