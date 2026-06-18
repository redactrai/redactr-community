package scanner_test

import (
	"strings"
	"testing"

	"github.com/redactrai/redactr-community/internal/scanner"
)

func TestRedact_Email(t *testing.T) {
	s := scanner.New()
	text := "Contact us at john.doe@example.com for more info."
	got, n, err := s.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 redaction, got 0")
	}
	if strings.Contains(got, "john.doe@example.com") {
		t.Errorf("email was not redacted; got: %s", got)
	}
	if !strings.Contains(got, "[REDACTED-EMAIL]") {
		t.Errorf("expected [REDACTED-EMAIL] in output; got: %s", got)
	}
}

func TestRedact_AWSAccessKey(t *testing.T) {
	s := scanner.New()
	text := "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in your env."
	got, n, err := s.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 redaction, got 0")
	}
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS access key was not redacted; got: %s", got)
	}
	if !strings.Contains(got, "[REDACTED-AWS-ACCESS-KEY]") {
		t.Errorf("expected [REDACTED-AWS-ACCESS-KEY] in output; got: %s", got)
	}
}

func TestRedact_ConnectionString(t *testing.T) {
	s := scanner.New()
	text := "DATABASE_URL=postgres://user:password@localhost:5432/mydb"
	got, n, err := s.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 redaction, got 0")
	}
	if strings.Contains(got, "postgres://user:password@localhost:5432/mydb") {
		t.Errorf("connection string was not redacted; got: %s", got)
	}
	if !strings.Contains(got, "[REDACTED-CONNECTION-STRING]") {
		t.Errorf("expected [REDACTED-CONNECTION-STRING] in output; got: %s", got)
	}
}

func TestRedact_SSN(t *testing.T) {
	s := scanner.New()
	text := "My social security number is 123-45-6789."
	got, n, err := s.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 redaction, got 0")
	}
	if strings.Contains(got, "123-45-6789") {
		t.Errorf("SSN was not redacted; got: %s", got)
	}
	if !strings.Contains(got, "[REDACTED-SSN]") {
		t.Errorf("expected [REDACTED-SSN] in output; got: %s", got)
	}
}

func TestRedact_Prose_NoRedactions(t *testing.T) {
	s := scanner.New()
	text := "The quick brown fox jumps over the lazy dog. It was a sunny afternoon in the park."
	got, n, err := s.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 redactions for plain prose, got %d; result: %s", n, got)
	}
	if got != text {
		t.Errorf("expected text unchanged; got: %s", got)
	}
}

func TestRedact_EnclosedMatchPrefersWidest(t *testing.T) {
	s := scanner.New()
	out, n, err := s.Redact("db postgres://user@example.com:5432/db done")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "example.com") {
		t.Errorf("secret leaked: %q", out)
	}
	if strings.Contains(out, "[REDACTED-EMAIL]") {
		t.Errorf("inner email won over connection string: %q", out)
	}
	if !strings.Contains(out, "[REDACTED-CONNECTION-STRING]") {
		t.Errorf("connection string not redacted: %q", out)
	}
	if n < 1 {
		t.Errorf("expected >=1 redaction, got %d", n)
	}
}

func TestRedact_MultipleFindings_RightToLeft(t *testing.T) {
	s := scanner.New()
	// Both an email and an AWS key in the same string — both should be redacted
	text := "Email: user@test.com and key AKIAIOSFODNN7EXAMPLE here."
	got, n, err := s.Redact(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n < 2 {
		t.Errorf("expected at least 2 redactions, got %d; result: %s", n, got)
	}
	if strings.Contains(got, "user@test.com") {
		t.Errorf("email not redacted; got: %s", got)
	}
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key not redacted; got: %s", got)
	}
}
