package proxy

import "testing"

func TestAllowlist_Match(t *testing.T) {
	a := NewAllowlist([]string{"api.anthropic.com", "*.githubcopilot.com"})
	cases := map[string]bool{
		"api.anthropic.com:443":               true,
		"api.anthropic.com":                   true,
		"copilot.githubcopilot.com:443":       true,
		"api.githubcopilot.com:443":           true,
		"example.com:443":                     false,
		"evil-api.anthropic.com.evil.com:443": false,
	}
	for host, want := range cases {
		if got := a.Match(host); got != want {
			t.Errorf("Match(%q)=%v want %v", host, got, want)
		}
	}
}
