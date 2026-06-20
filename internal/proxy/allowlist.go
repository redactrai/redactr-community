package proxy

import (
	"bufio"
	"os"
	"strings"
)

// DefaultAllowHosts are the AI-provider hosts MITM-decrypted by default.
// Everything else is tunnelled untouched. Extend via ~/.redactr/allow.txt
// or with: redactr allow <host>
// NOTE: antigravity's exact endpoints are unconfirmed (see plan Task 7).
var DefaultAllowHosts = []string{
	"api.anthropic.com",
	"api.openai.com",
	"chatgpt.com",
	"*.githubcopilot.com",
	"copilot-proxy.githubusercontent.com",
	"generativelanguage.googleapis.com",
	"cloudcode-pa.googleapis.com",
}

type Allowlist struct{ patterns []string }

func NewAllowlist(hosts []string) *Allowlist {
	ps := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" && !strings.HasPrefix(h, "#") {
			ps = append(ps, h)
		}
	}
	return &Allowlist{patterns: ps}
}

func hostOnly(hostport string) string {
	h := strings.ToLower(hostport)
	if i := strings.LastIndex(h, ":"); i != -1 {
		h = h[:i]
	}
	return h
}

func (a *Allowlist) Match(hostport string) bool {
	host := hostOnly(hostport)
	for _, p := range a.patterns {
		if strings.HasPrefix(p, "*.") {
			if host == p[2:] || strings.HasSuffix(host, p[1:]) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// LoadAllowlist returns defaults plus any user entries in path (one host/line).
func LoadAllowlist(path string) *Allowlist {
	hosts := append([]string(nil), DefaultAllowHosts...)
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			hosts = append(hosts, s.Text())
		}
	}
	return NewAllowlist(hosts)
}
