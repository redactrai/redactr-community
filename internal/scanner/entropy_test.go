package scanner

import (
	"strings"
	"testing"
)

// TestEntropy_CatchesRandomSecret verifies that a high-entropy token with no
// recognizable regex prefix is redacted via entropy detection.
// The input uses "config:" context which is NOT a keyword in any regex pattern,
// so only the entropy heuristic can catch the 40-char mixed-case+digit secret.
func TestEntropy_CatchesRandomSecret(t *testing.T) {
	s := New()
	// bare high-entropy token with no regex-triggering keyword prefix
	in := `config: f3Kq9zR2pX7wL4mN8vC1bH6tY0sD5gJ2aE4uI9o`
	out, n, err := s.Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || strings.Contains(out, "f3Kq9zR2pX7wL4mN8vC1bH6tY0sD5gJ2aE4uI9o") {
		t.Fatalf("expected high-entropy token redacted, got: %s", out)
	}
}

func TestEntropy_LeavesProseAlone(t *testing.T) {
	s := New()
	in := "The quick brown fox jumps over the lazy dog and writes documentation."
	out, n, err := s.Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || out != in {
		t.Fatalf("prose should be untouched, got n=%d out=%s", n, out)
	}
}

func TestEntropy_NoDoubleCountWithRegex(t *testing.T) {
	s := New()
	// An AWS-style key should be caught by regex, not also double-flagged.
	res, err := s.Scan("AKIAIOSFODNN7EXAMPLE here")
	if err != nil {
		t.Fatal(err)
	}
	// no two findings should cover overlapping ranges
	for i := 0; i < len(res.Findings); i++ {
		for j := i + 1; j < len(res.Findings); j++ {
			a, b := res.Findings[i], res.Findings[j]
			if a.Start < b.End && b.Start < a.End {
				t.Fatalf("overlapping findings: %+v and %+v", a, b)
			}
		}
	}
}
