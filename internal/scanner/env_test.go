package scanner

import (
	"strings"
	"testing"
)

// TestEnvSecrets verifies that .env-style secret assignments — including keys
// with prefixes/suffixes that plain GENERIC-SECRET misses — get redacted, so an
// AI tool reading a .env file never sees the values.
func TestEnvSecrets(t *testing.T) {
	s := New()
	env := strings.Join([]string{
		"DATABASE_PASSWORD=sup3rs3cretdbpass",
		"STRIPE_API_KEY=sk_live_abc123def456ghi789",
		"GITHUB_ACCESS_KEY=ghp_aaaaaaaaaaaaaaaaaaaa",
		"MY_CLIENT_SECRET=zzzzzzzzzzzz",
		"PUBLIC_URL=https://example.com",   // not a secret — should remain
		"APP_NAME=redactr",                  // not a secret — should remain
	}, "\n")

	out, n, err := s.Redact(env)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected env secrets to be redacted")
	}
	for _, leaked := range []string{"sup3rs3cretdbpass", "sk_live_abc123def456ghi789", "ghp_aaaaaaaaaaaaaaaaaaaa", "zzzzzzzzzzzz"} {
		if strings.Contains(out, leaked) {
			t.Errorf("secret leaked through: %q\nout:\n%s", leaked, out)
		}
	}
	// Non-secret config should survive.
	if !strings.Contains(out, "redactr") {
		t.Errorf("non-secret APP_NAME value was over-redacted:\n%s", out)
	}
}
