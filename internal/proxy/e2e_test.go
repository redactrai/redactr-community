package proxy_test

// e2e_test.go proves that secrets are stripped from request bodies end-to-end
// through the real running proxy over plain HTTP (no TLS/MITM setup needed —
// the DoFunc redaction runs for plain HTTP requests just like HTTPS).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/redactrai/redactr-community/internal/certgen"
	"github.com/redactrai/redactr-community/internal/proxy"
	"github.com/redactrai/redactr-community/internal/scanner"
)

// startProxy creates a temp home dir, builds a CA, wires up the scanner, and
// starts the proxy on an ephemeral port. Returns the proxy URL and a cleanup func.
func startProxy(t *testing.T) *url.URL {
	t.Helper()

	tmp := t.TempDir()
	// Redirect HOME so proxy's config/allowlist load from the temp dir, not the
	// real $HOME. This avoids interference with user's ~/.redactr files.
	t.Setenv("HOME", tmp)

	ca, err := certgen.LoadOrCreateCA(tmp+"/ca.pem", tmp+"/ca.key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	sc := scanner.New()
	find := func(text string) []proxy.Replacement {
		res, _ := sc.Scan(text)
		var out []proxy.Replacement
		for _, f := range res.Findings {
			if f.Value != "" {
				out = append(out, proxy.Replacement{Old: f.Value, New: "[REDACTED-" + f.Label + "]"})
			}
		}
		return out
	}
	p, err := proxy.New(ca, find, nil)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	addr, err := p.Start(0) // 0 → OS picks ephemeral port
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop() })

	proxyURL, err := url.Parse(addr)
	if err != nil {
		t.Fatalf("parse proxy addr %q: %v", addr, err)
	}
	return proxyURL
}

// TestE2E_RedactsThroughProxy proves that all four secret families are stripped
// from the body that reaches the upstream server and that X-Redactr-Status is set.
func TestE2E_RedactsThroughProxy(t *testing.T) {
	proxyURL := startProxy(t)

	// Capture the raw body the upstream receives.
	var (
		mu           sync.Mutex
		receivedBody string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	// POST a JSON body containing four distinct secret families:
	//   1. AWS access key     (AWS-ACCESS-KEY pattern)
	//   2. High-entropy token (HIGH-ENTROPY heuristic)
	//   3. Stripe secret key  (ENV-SECRET pattern)
	//   4. Email address      (EMAIL pattern)
	const secretAWSKey = "AKIAIOSFODNN7EXAMPLE"
	const secretEntropy = "f3Kq9zR2pX7wL4mN8vC1bH6tY0sD5gJ2aE4uI9o"
	const secretStripe = "sk_live_51HxxxxxxxxxxQQQ"
	const secretEmail = "leak@example.com"

	body := `{"model":"x","messages":[{"role":"user","content":"my config:\n` +
		secretAWSKey + `\ntoken ` + secretEntropy +
		`\nSTRIPE_SECRET_KEY=` + secretStripe +
		`\nmail ` + secretEmail + `"}]}`

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Post(upstream.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	mu.Lock()
	got := receivedBody
	mu.Unlock()

	// --- Assertion 1: no raw secret reached the upstream ---
	for _, secret := range []string{secretAWSKey, secretEntropy, secretStripe, secretEmail} {
		if strings.Contains(got, secret) {
			t.Errorf("secret leaked to upstream — raw value %q found in body: %s", secret, got)
		}
	}

	// --- Assertion 2: redaction placeholder is present ---
	if !strings.Contains(got, "[REDACTED-") {
		t.Errorf("expected '[REDACTED-' placeholder in upstream body, got: %s", got)
	}

	// --- Assertion 3: proxy stamped X-Redactr-Status ---
	status := resp.Header.Get("X-Redactr-Status")
	if status == "" {
		t.Errorf("expected non-empty X-Redactr-Status header, got empty string")
	}
}

// TestE2E_CleanRequestUnchanged proves that a body with no secrets reaches the
// upstream unchanged and that X-Redactr-Status is "clean".
func TestE2E_CleanRequestUnchanged(t *testing.T) {
	proxyURL := startProxy(t)

	var (
		mu           sync.Mutex
		receivedBody string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	const cleanBody = `{"model":"x","messages":[{"role":"user","content":"hello how are you"}]}`

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Post(upstream.URL, "application/json", strings.NewReader(cleanBody))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	mu.Lock()
	got := receivedBody
	mu.Unlock()

	// Body must arrive byte-for-byte unchanged (proxy returns original bytes when count == 0).
	if got != cleanBody {
		t.Errorf("expected upstream to receive body unchanged\nwant: %s\ngot:  %s", cleanBody, got)
	}

	// X-Redactr-Status must be "clean".
	status := resp.Header.Get("X-Redactr-Status")
	if status != "clean" {
		t.Errorf("expected X-Redactr-Status: clean, got %q", status)
	}
}
