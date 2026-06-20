package filescan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redactrai/redactr-community/internal/filescan"
	"github.com/redactrai/redactr-community/internal/scanner"
)

func TestScan_findsSecretsInDotEnv(t *testing.T) {
	tmp := t.TempDir()

	// Write a .env file with two secrets
	envContent := "DATABASE_PASSWORD=sup3rs3cretval123\nAPI_TOKEN=tok_abcdef123456\n"
	if err := os.WriteFile(filepath.Join(tmp, ".env"), []byte(envContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a clean file
	if err := os.WriteFile(filepath.Join(tmp, "notes.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := scanner.New()
	findings, err := filescan.Scan(tmp, sc)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Must have at least 2 findings
	if len(findings) < 2 {
		t.Fatalf("expected >=2 findings, got %d: %+v", len(findings), findings)
	}

	// All findings must come from .env, none from notes.txt
	for _, f := range findings {
		if !strings.HasSuffix(f.Path, ".env") {
			t.Errorf("unexpected finding in non-.env file: %s", f.Path)
		}
	}
}

func TestRedactFile_removesSecretsAndPreservesStructure(t *testing.T) {
	tmp := t.TempDir()

	envContent := "DATABASE_PASSWORD=sup3rs3cretval123\nAPI_TOKEN=tok_abcdef123456\nDEBUG=true\n"
	envPath := filepath.Join(tmp, ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := scanner.New()
	n, err := filescan.RedactFile(envPath, sc)
	if err != nil {
		t.Fatalf("RedactFile returned error: %v", err)
	}
	if n == 0 {
		t.Fatal("expected >0 redactions, got 0")
	}

	// Re-read and verify secrets are gone
	b, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)

	if strings.Contains(content, "sup3rs3cretval123") {
		t.Error("secret 'sup3rs3cretval123' still present after redaction")
	}
	if strings.Contains(content, "tok_abcdef123456") {
		t.Error("secret 'tok_abcdef123456' still present after redaction")
	}

	// File should still contain other non-secret lines
	if !strings.Contains(content, "DEBUG=true") {
		t.Error("non-secret line 'DEBUG=true' was removed by redaction")
	}
}
