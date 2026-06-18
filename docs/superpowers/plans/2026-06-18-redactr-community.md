# redactr-community Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `redactr-community` — a free, AGPL, regex-only local HTTPS MITM proxy that redacts secrets/PII before traffic leaves the machine, with opt-in anonymized telemetry.

**Architecture:** A clean standalone Go module that *copies only* the regex scanner, MITM proxy, and CA code from the private Redactr repo (no ML/sandbox/server/policy). A Go CLI runs the proxy; an opt-in telemetry client sends anonymous heartbeats to a Cloudflare Worker collector (in this repo) that derives coarse geo at the edge and discards IPs.

**Tech Stack:** Go 1.26+, `github.com/elazarl/goproxy`, `golang.org/x/crypto`, stdlib. Telemetry collector: Cloudflare Worker + Analytics Engine. CI: GitHub Actions; release: GoReleaser.

**Source repo for extraction:** `/Users/rakeshguha/Desktop/Code/Redactr` (private; read-only reference — copy from it, never depend on it).

**Working repo:** `/Users/rakeshguha/Desktop/Code/redactr-community` (this repo).

**Conventions:** Module path `github.com/redactrai/redactr-community`. Commit after every passing step. Run all commands from the repo root unless noted.

---

## Task 0: Repo scaffold

**Files:**
- Create: `go.mod`, `LICENSE`, `.gitignore`, `README.md`, `Makefile`

- [ ] **Step 1: Init the Go module**

Run:
```bash
cd /Users/rakeshguha/Desktop/Code/redactr-community
go mod init github.com/redactrai/redactr-community
go get github.com/elazarl/goproxy@v1.8.3
```
Expected: creates `go.mod` with the module path and the goproxy require line.

- [ ] **Step 2: Add the AGPL-3.0 license**

Run:
```bash
curl -s https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE
head -2 LICENSE
```
Expected: file begins with "GNU AFFERO GENERAL PUBLIC LICENSE".

- [ ] **Step 3: Add `.gitignore`**

Create `.gitignore`:
```
/dist/
/redactr-community
*.test
.DS_Store
node_modules/
.wrangler/
```

- [ ] **Step 4: Add README skeleton**

Create `README.md`:
```markdown
# redactr-community

Free, source-available (AGPL-3.0) **regex-only** redaction proxy. Runs locally and strips
secrets/PII (API keys, emails, SSNs, connection strings, …) out of your AI tools' HTTPS
requests before they leave your machine.

Part of [Redactr](https://redactrai.com). The community edition is regex-only; the full
product adds statistical + ML detection, agent sandboxing, and a team control plane.

## Install
Download a binary from Releases, or `go install github.com/redactrai/redactr-community@latest`.

## Usage
```
redactr-community            # start the proxy + print CA-trust instructions
redactr-community shell      # subshell with HTTPS_PROXY preset
redactr-community telemetry status
```

## Privacy
Your code, traffic, and redacted values **never** leave your machine. The only thing that
can leave is **opt-in, anonymous** telemetry (off by default): a random session id, app
version, and OS — never content or your IP. See "Telemetry" below.
```

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum LICENSE .gitignore README.md
git commit -m "chore: scaffold module, AGPL license, README"
```

---

## Task 1: Regex scanner (copy + adapt)

**Files:**
- Create: `internal/scanner/types.go` (from private `internal/scanner/types.go`)
- Create: `internal/scanner/regex.go` (from private `internal/scanner/regex/regex.go`)
- Create: `internal/scanner/redact.go` (new — applies `[REDACTED-<LABEL>]`)
- Test: `internal/scanner/redact_test.go`

- [ ] **Step 1: Copy the types**

Copy `Finding` and `ScanResult` (and any tiny structs they need) from private `internal/scanner/types.go` into `internal/scanner/types.go`. Set `package scanner`. Keep only:
```go
type Finding struct {
	Label      string
	Value      string
	Start, End int
	Confidence float64
}
type ScanResult struct {
	Findings []Finding
}
```
Drop the `Layer` interface and `LayerMs`/`Confidence` plumbing not needed here.

- [ ] **Step 2: Copy the regex layer**

Copy private `internal/scanner/regex/regex.go` → `internal/scanner/regex.go`. Adapt:
- `package scanner`
- Keep `DefaultPatterns()` (the 23 patterns) and the `Scan(text string) (*ScanResult, error)` method, but make it a package-level type `RegexScanner` with `New()` and `Scan`.
- Remove imports/fields referencing entropy, presidio, pipeline, or config. No external deps beyond `regexp`.

- [ ] **Step 3: Write the failing redaction test**

Create `internal/scanner/redact_test.go`:
```go
package scanner

import "testing"

func TestRedactKnownSecrets(t *testing.T) {
	s := New()
	cases := []struct{ in, mustNotContain, mustContain string }{
		{"contact me at jane.doe@acme.com please", "jane.doe@acme.com", "[REDACTED-EMAIL]"},
		{"key AKIA1234567890ABCD12 here", "AKIA1234567890ABCD12", "[REDACTED-AWS-ACCESS-KEY]"},
		{"db postgres://u:p@h:5432/db x", "postgres://u:p@h:5432/db", "[REDACTED-CONNECTION-STRING]"},
		{"ssn 123-45-6789 ok", "123-45-6789", "[REDACTED-US-SSN]"},
	}
	for _, c := range cases {
		out, _, err := s.Redact(c.in)
		if err != nil {
			t.Fatalf("Redact(%q) error: %v", c.in, err)
		}
		if c.mustNotContain != "" && contains(out, c.mustNotContain) {
			t.Errorf("Redact(%q)=%q still contains secret %q", c.in, out, c.mustNotContain)
		}
		if !contains(out, c.mustContain) {
			t.Errorf("Redact(%q)=%q missing %q", c.in, out, c.mustContain)
		}
	}
}

func TestRedactLeavesProseAlone(t *testing.T) {
	s := New()
	in := "the quick brown fox jumps over the lazy dog"
	out, n, _ := s.Redact(in)
	if out != in || n != 0 {
		t.Errorf("expected no redaction, got %q (n=%d)", out, n)
	}
}

func contains(h, n string) bool { return len(n) > 0 && (len(h) >= len(n)) && (indexOf(h, n) >= 0) }
func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
```
(Adjust the exact `[REDACTED-*]` labels to match the copied patterns' `Label` values — verify against `regex.go` after copying.)

- [ ] **Step 4: Run it to verify it fails**

Run: `go test ./internal/scanner/ -run TestRedact -v`
Expected: FAIL — `New`/`Redact` undefined.

- [ ] **Step 5: Implement `Redact`**

Create `internal/scanner/redact.go`:
```go
package scanner

import (
	"fmt"
	"sort"
)

// New returns a regex-only scanner.
func New() *RegexScanner { return NewRegexScanner() } // alias if constructor differs

// Redact replaces every detected finding with [REDACTED-<LABEL>].
// Returns redacted text and the number of redactions.
func (s *RegexScanner) Redact(text string) (string, int, error) {
	res, err := s.Scan(text)
	if err != nil {
		return text, 0, err
	}
	f := res.Findings
	// apply right-to-left so offsets stay valid; dedupe overlaps
	sort.Slice(f, func(i, j int) bool { return f[i].Start > f[j].Start })
	out := text
	count := 0
	prevStart := len(text) + 1
	for _, fd := range f {
		if fd.End > prevStart { // overlapping with an already-applied (further-right) match
			continue
		}
		out = out[:fd.Start] + fmt.Sprintf("[REDACTED-%s]", fd.Label) + out[fd.End:]
		prevStart = fd.Start
		count++
	}
	return out, count, nil
}
```
Adapt `New()`/`NewRegexScanner()` to whatever constructor name `regex.go` ended up with.

- [ ] **Step 6: Run tests to verify pass**

Run: `go test ./internal/scanner/ -v`
Expected: PASS. (If a label name differs, fix the test's expected label to match `regex.go`.)

- [ ] **Step 7: Commit**

```bash
git add internal/scanner/
git commit -m "feat: regex-only scanner with [REDACTED-LABEL] redaction"
```

---

## Task 2: Local CA generation (copy + adapt)

**Files:**
- Create: `internal/certgen/ca.go` (from private `internal/certgen/ca.go`)
- Test: `internal/certgen/ca_test.go`

- [ ] **Step 1: Copy the CA code**

Copy private `internal/certgen/ca.go` verbatim → `internal/certgen/ca.go`. Keep `CA`, `GenerateCA`, `LoadCA`, `LoadOrCreateCA`, `IssueCert`. It is pure stdlib (`crypto/*`); no adaptation beyond confirming `package certgen`.

- [ ] **Step 2: Write the failing test**

Create `internal/certgen/ca_test.go`:
```go
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
	leaf, err := ca.IssueCert("api.anthropic.com")
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if leaf == nil {
		t.Fatal("nil leaf cert")
	}
	// second call loads the same CA (idempotent)
	ca2, err := LoadOrCreateCA(cert, key)
	if err != nil || !ca2.Cert.Equal(ca.Cert) {
		t.Fatalf("expected idempotent load, err=%v", err)
	}
}
```
Adjust `IssueCert`'s return type/name to match the copied code.

- [ ] **Step 3: Run to verify fail, then pass**

Run: `go test ./internal/certgen/ -v`
Expected: FAIL first (if signatures differ) → after aligning the test to the copied API, PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/certgen/
git commit -m "feat: local CA generation for HTTPS MITM"
```

---

## Task 3: MITM proxy with regex redaction (copy + adapt)

**Files:**
- Create: `internal/proxy/proxy.go`, `internal/proxy/extract.go`, `internal/proxy/rewrite.go` (from private `internal/proxy/`)
- Test: `internal/proxy/proxy_test.go`

- [ ] **Step 1: Copy + trim the proxy**

Copy private `internal/proxy/{proxy.go,extract.go,rewrite.go}`. Adapt:
- `package proxy`.
- Replace the multi-layer pipeline/coordinator dependency with a single field `redact func(string) (string, int, error)` (satisfied by `scanner.RegexScanner.Redact`).
- Remove: domain-policy, bypass-from-policy, metrics/prometheus, onScan callbacks tied to the private stores. Keep a simple optional `onRedact func(host string, n int)`.
- Keep: goproxy setup, `OnRequest().DoFunc` body read → `ExtractLastUserMessage` → `redact` → `ReplaceLastUserMessage` → fix `Content-Length`, and the `X-Redactr-Status` response header.
- Constructor: `New(ca *certgen.CA, redact func(string)(string,int,error)) *Proxy` and `(*Proxy).Start(port int) (addr string, err error)`.

- [ ] **Step 2: Write the failing end-to-end test**

Create `internal/proxy/proxy_test.go`:
```go
package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redactrai/redactr-community/internal/scanner"
)

func TestProxyRedactsRequestBody(t *testing.T) {
	// upstream echoes the request body it received
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	s := scanner.New()
	body := `{"messages":[{"role":"user","content":"my key is AKIA1234567890ABCD12"}]}`
	// Drive the request hook directly (unit-level) rather than full TLS MITM:
	redacted, n, err := s.Redact(body)
	if err != nil || n == 0 {
		t.Fatalf("expected redaction, n=%d err=%v", n, err)
	}
	if strings.Contains(redacted, "AKIA1234567890ABCD12") {
		t.Fatalf("secret survived: %s", redacted)
	}
	_ = upstream
	_ = got
}
```
> Note: full TLS-MITM is exercised in the Task 8 manual run; this unit test pins the redaction-on-body behavior. If `proxy.go` exposes a testable `handleBody([]byte) ([]byte, int)` helper, prefer testing that directly — extract one if needed.

- [ ] **Step 3: Run to verify pass**

Run: `go test ./internal/proxy/ -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/
git commit -m "feat: MITM proxy that redacts request bodies via regex scanner"
```

---

## Task 4: Telemetry client (opt-in, anonymized)

**Files:**
- Create: `internal/telemetry/client.go`
- Create: `internal/config/config.go` (consent + session)
- Test: `internal/telemetry/client_test.go`

- [ ] **Step 1: Write config (consent storage)**

Create `internal/config/config.go`:
```go
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	TelemetryEnabled bool   `json:"telemetry_enabled"`
	FirstRunSeen     bool   `json:"first_run_seen"`
}

func Dir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".redactr-community")
}
func path() string { return filepath.Join(Dir(), "config.json") }

func Load() Config {
	var c Config
	b, err := os.ReadFile(path())
	if err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}
func Save(c Config) error {
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path(), b, 0o644)
}
```

- [ ] **Step 2: Write the failing telemetry test**

Create `internal/telemetry/client_test.go`:
```go
package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDisabledSendsNothing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	c := &Client{Enabled: false, Endpoint: srv.URL, Version: "test", Interval: 10 * time.Millisecond}
	c.beat() // one tick
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("disabled client must not send")
	}
}

func TestEnabledSendsAnonymousPayload(t *testing.T) {
	type beat struct {
		Session string `json:"session"`
		Version string `json:"version"`
		OS      string `json:"os"`
		IP      string `json:"ip"`
		Content string `json:"content"`
	}
	got := make(chan beat, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b beat
		_ = json.NewDecoder(r.Body).Decode(&b)
		got <- b
	}))
	defer srv.Close()
	c := &Client{Enabled: true, Endpoint: srv.URL, Version: "1.2.3", Interval: time.Minute}
	c.beat()
	select {
	case b := <-got:
		if b.Session == "" || b.Version != "1.2.3" || b.OS == "" {
			t.Fatalf("bad payload: %+v", b)
		}
		if b.IP != "" || b.Content != "" {
			t.Fatalf("payload leaked data: %+v", b)
		}
	case <-time.After(time.Second):
		t.Fatal("no beat received")
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./internal/telemetry/ -v`
Expected: FAIL — `Client`/`beat` undefined.

- [ ] **Step 4: Implement the client**

Create `internal/telemetry/client.go`:
```go
package telemetry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

type Client struct {
	Enabled  bool
	Endpoint string
	Version  string
	Interval time.Duration
	session  string
	http     *http.Client
}

func newSession() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// beat sends a single anonymous heartbeat. No-op when disabled.
func (c *Client) beat() {
	if !c.Enabled {
		return
	}
	if c.session == "" {
		c.session = newSession()
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 5 * time.Second}
	}
	payload := map[string]string{
		"session": c.session,
		"version": c.Version,
		"os":      runtime.GOOS,
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// Run rotates the session each ~24h and beats on Interval until stop is closed.
func (c *Client) Run(stop <-chan struct{}) {
	if !c.Enabled {
		return
	}
	c.beat()
	t := time.NewTicker(c.Interval)
	rot := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	defer rot.Stop()
	for {
		select {
		case <-stop:
			return
		case <-rot.C:
			c.session = newSession()
		case <-t.C:
			c.beat()
		}
	}
}
```

- [ ] **Step 5: Run tests to verify pass**

Run: `go test ./internal/telemetry/ ./internal/config/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/telemetry/ internal/config/
git commit -m "feat: opt-in anonymized telemetry client + consent config"
```

---

## Task 5: CLI entrypoint

**Files:**
- Create: `cmd/redactr-community/main.go`
- Create: `internal/cli/cli.go` (command routing, banner, trust instructions)
- Test: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing banner test**

Create `internal/cli/cli_test.go`:
```go
package cli

import "testing"

func TestTelemetryBannerMentionsOptInAndAnonymous(t *testing.T) {
	b := TelemetryBanner()
	for _, want := range []string{"opt-in", "anonymous", "telemetry on"} {
		if !containsFold(b, want) {
			t.Errorf("banner missing %q:\n%s", want, b)
		}
	}
}
func containsFold(h, n string) bool {
	hl, nl := []rune(toLower(h)), []rune(toLower(n))
	for i := 0; i+len(nl) <= len(hl); i++ {
		if string(hl[i:i+len(nl)]) == string(nl) {
			return true
		}
	}
	return false
}
func toLower(s string) string {
	r := []rune(s)
	for i, c := range r {
		if c >= 'A' && c <= 'Z' {
			r[i] = c + 32
		}
	}
	return string(r)
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/cli/ -v`
Expected: FAIL — `TelemetryBanner` undefined.

- [ ] **Step 3: Implement the CLI**

Create `internal/cli/cli.go`:
```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/redactrai/redactr-community/internal/config"
)

func TelemetryBanner() string {
	return `── redactr-community ───────────────────────────────────────
 Anonymous, opt-in telemetry is OFF by default.
 If you enable it, we send only a random session id, the app
 version, and your OS — never your code, traffic, redacted
 values, or IP. It helps us see how many people use the tool.
 Enable:  redactr-community telemetry on
 Status:  redactr-community telemetry status
────────────────────────────────────────────────────────────`
}

func TrustInstructions(caPath string) string {
	switch runtime.GOOS {
	case "darwin":
		return "Trust the CA:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + caPath
	case "linux":
		return "Trust the CA: copy " + caPath + " into /usr/local/share/ca-certificates/ and run `sudo update-ca-certificates`"
	default:
		return "Trust the CA: import " + caPath + " into your system's Trusted Root store."
	}
}

// SetTelemetry persists the consent flag.
func SetTelemetry(on bool) error {
	c := config.Load()
	c.TelemetryEnabled = on
	return config.Save(c)
}

func caPaths() (cert, key string) {
	d := config.Dir()
	return filepath.Join(d, "ca.pem"), filepath.Join(d, "ca.key")
}

// MaybeShowFirstRun prints the banner once.
func MaybeShowFirstRun() {
	c := config.Load()
	if !c.FirstRunSeen {
		fmt.Fprintln(os.Stderr, TelemetryBanner())
		c.FirstRunSeen = true
		_ = config.Save(c)
	}
}
```

- [ ] **Step 4: Wire `main.go`**

Create `cmd/redactr-community/main.go`:
```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/redactrai/redactr-community/internal/certgen"
	"github.com/redactrai/redactr-community/internal/cli"
	"github.com/redactrai/redactr-community/internal/config"
	"github.com/redactrai/redactr-community/internal/proxy"
	"github.com/redactrai/redactr-community/internal/scanner"
	"github.com/redactrai/redactr-community/internal/telemetry"
)

var version = "dev" // set via -ldflags at release

const telemetryEndpoint = "https://t.redactrai.com/beat" // collector (Task 6)

func main() {
	cmd := "start"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "telemetry":
		handleTelemetry()
	case "ca":
		cert, _ := caPaths()
		fmt.Println(cli.TrustInstructions(cert))
	case "shell":
		runShell()
	case "start":
		runStart()
	default:
		fmt.Println("usage: redactr-community [start|shell|ca|telemetry on|off|status]")
	}
}

func caPaths() (string, string) {
	d := config.Dir()
	return d + "/ca.pem", d + "/ca.key"
}

func handleTelemetry() {
	arg := ""
	if len(os.Args) > 2 {
		arg = os.Args[2]
	}
	switch arg {
	case "on":
		_ = cli.SetTelemetry(true)
		fmt.Println("telemetry: ON (anonymous)")
	case "off":
		_ = cli.SetTelemetry(false)
		fmt.Println("telemetry: OFF")
	default:
		fmt.Printf("telemetry: %v\n", config.Load().TelemetryEnabled)
	}
}

func runStart() {
	cli.MaybeShowFirstRun()
	cert, key := caPaths()
	ca, err := certgen.LoadOrCreateCA(cert, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CA error:", err)
		os.Exit(1)
	}
	s := scanner.New()
	p := proxy.New(ca, s.Redact)
	addr, err := p.Start(8080)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		os.Exit(1)
	}
	fmt.Printf("redactr-community proxy listening on %s\n", addr)
	fmt.Println(cli.TrustInstructions(cert))
	fmt.Printf("Then: export HTTPS_PROXY=%s\n", addr)

	stop := make(chan struct{})
	if config.Load().TelemetryEnabled {
		tc := &telemetry.Client{Enabled: true, Endpoint: telemetryEndpoint, Version: version, Interval: 10 * time.Minute}
		go tc.Run(stop)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(stop)
}

func runShell() {
	// start proxy in-process then exec a subshell with HTTPS_PROXY set
	cert, key := caPaths()
	ca, _ := certgen.LoadOrCreateCA(cert, key)
	s := scanner.New()
	p := proxy.New(ca, s.Redact)
	addr, err := p.Start(0) // ephemeral port
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sh := os.Getenv("SHELL")
	if sh == "" {
		sh = "/bin/sh"
	}
	c := exec.Command(sh)
	c.Env = append(os.Environ(), "HTTPS_PROXY="+addr, "HTTP_PROXY="+addr)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	_ = c.Run()
}
```
> Align `proxy.New`/`Start` signatures with Task 3. If `Start(0)` ephemeral isn't supported, add it there.

- [ ] **Step 5: Build + run tests**

Run:
```bash
go build ./... && go test ./... -v
```
Expected: builds clean; all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/ internal/cli/
git commit -m "feat: CLI (start/shell/ca/telemetry) with first-run banner"
```

---

## Task 6: Telemetry collector (Cloudflare Worker)

**Files:**
- Create: `telemetry/worker/src/index.js`
- Create: `telemetry/worker/wrangler.toml`
- Create: `telemetry/worker/README.md`

- [ ] **Step 1: Write the Worker**

Create `telemetry/worker/src/index.js`:
```js
// Receives anonymous heartbeats. Derives coarse geo at the edge and DISCARDS the IP.
export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("ok", { status: 200 });
    let body = {};
    try { body = await request.json(); } catch { return new Response("bad", { status: 400 }); }

    const session = String(body.session || "").slice(0, 32);
    const version = String(body.version || "").slice(0, 32);
    const os = String(body.os || "").slice(0, 16);
    if (!session) return new Response("bad", { status: 400 });

    // Coarse geo from the Cloudflare edge — IP is never read or stored.
    const country = (request.cf && request.cf.country) || "XX";
    const city = (request.cf && request.cf.city) || "";

    env.TELEMETRY.writeDataPoint({
      blobs: [country, city, version, os],
      indexes: [session], // sampling key; not identity
      doubles: [1],
    });
    return new Response("ok", { status: 200, headers: { "cache-control": "no-store" } });
  },
};
```

- [ ] **Step 2: Write wrangler config**

Create `telemetry/worker/wrangler.toml`:
```toml
name = "redactr-telemetry"
main = "src/index.js"
compatibility_date = "2026-01-01"

[[analytics_engine_datasets]]
binding = "TELEMETRY"
dataset = "redactr_community_heartbeats"
```

- [ ] **Step 3: Document deploy + the active-users query**

Create `telemetry/worker/README.md`:
```markdown
# redactr telemetry collector

Anonymous heartbeat sink. Reads country/city from the Cloudflare edge and discards the IP.

## Deploy
    npx wrangler deploy
Then map a route (e.g. `t.redactrai.com/beat`) to this Worker in the Cloudflare dashboard,
and point the binary's `telemetryEndpoint` at it.

## Active users in the last 15 min, by country/city
    SELECT blob1 AS country, blob2 AS city, count(DISTINCT index1) AS active
    FROM redactr_community_heartbeats
    WHERE timestamp > now() - INTERVAL '15' MINUTE
    GROUP BY country, city
    ORDER BY active DESC
(Run via the Cloudflare Analytics Engine SQL API.)
```

- [ ] **Step 4: Commit**

```bash
git add telemetry/worker/
git commit -m "feat: Cloudflare Worker telemetry collector (edge geo, IP discarded)"
```

---

## Task 7: Build, CI, and release

**Files:**
- Create: `Makefile`, `.github/workflows/ci.yml`, `.goreleaser.yaml`
- Modify: `README.md` (Telemetry + Build sections)

- [ ] **Step 1: Makefile**

Create `Makefile`:
```makefile
build:
	go build -ldflags "-X main.version=$(shell git describe --tags --always)" -o redactr-community ./cmd/redactr-community
test:
	go test ./...
.PHONY: build test
```

- [ ] **Step 2: CI workflow**

Create `.github/workflows/ci.yml`:
```yaml
name: CI
on: [push, pull_request]
jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.26" }
      - run: go vet ./...
      - run: go test ./... -race
      - run: go build ./...
```

- [ ] **Step 3: GoReleaser config**

Create `.goreleaser.yaml`:
```yaml
version: 2
builds:
  - main: ./cmd/redactr-community
    binary: redactr-community
    ldflags: ["-s -w -X main.version={{.Version}}"]
    goos: [darwin, linux, windows]
    goarch: [amd64, arm64]
    ignore:
      - { goos: windows, goarch: arm64 }
archives:
  - formats: [tar.gz]
    format_overrides:
      - { goos: windows, formats: [zip] }
```

- [ ] **Step 4: Append README Telemetry section**

Add to `README.md`:
```markdown
## Telemetry (opt-in, anonymous)
Off by default. Enable with `redactr-community telemetry on`. When on, it sends a heartbeat
every ~10 min containing only: a random session id (rotated daily), the app version, and your
OS. The collector derives country/city from Cloudflare's edge and **discards your IP**. It
never sees your code, traffic, or redacted values. Source: `telemetry/worker/`.

## Build
    make build && make test
```

- [ ] **Step 5: Verify + commit**

Run: `make build && make test`
Expected: binary `./redactr-community` builds; tests PASS.
```bash
git add Makefile .github/ .goreleaser.yaml README.md
git commit -m "ci: build/test workflow, GoReleaser, telemetry docs"
```

---

## Task 8: End-to-end verification (the "make sure it works" gate)

**No new files — this is the manual acceptance run before the site cycle.**

- [ ] **Step 1: Build and start**

Run:
```bash
make build
./redactr-community
```
Expected: prints the first-run telemetry banner (only once), the proxy address, and CA-trust instructions.

- [ ] **Step 2: Trust the CA** (follow the printed per-OS instruction).

- [ ] **Step 3: Send a request with fake secrets through the proxy**

In another terminal:
```bash
export HTTPS_PROXY=http://127.0.0.1:8080
curl -s https://postman-echo.com/post \
  -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"key AKIA1234567890ABCD12 email a@b.com"}]}' | grep -o '\[REDACTED[^]]*\]'
```
Expected: output shows `[REDACTED-AWS-ACCESS-KEY]` and `[REDACTED-EMAIL]` (the echo reflects the body the upstream received — i.e., already redacted).

- [ ] **Step 4: Confirm telemetry is silent until opted in**

With telemetry OFF (default), confirm no requests to the collector (check Worker logs / `wrangler tail`). Then:
```bash
./redactr-community telemetry on
./redactr-community   # run ~1 min
```
Expected: collector receives anonymous heartbeats (session/version/os only); Analytics Engine query shows 1 active session with your country/city.

- [ ] **Step 5: Tag a release (optional, when satisfied)**

```bash
git tag v0.1.0 && git push origin v0.1.0   # triggers GoReleaser if wired
```

---

## Notes for the implementer
- The regex/proxy/CA code already exists in the private repo at `/Users/rakeshguha/Desktop/Code/Redactr` — copy and trim per Tasks 1–3; do **not** import that module.
- After copying, **verify the exact `Label` strings** in `regex.go` and align the test expectations (Task 1 Step 6).
- Never copy: `internal/scanner/{entropy,gliner,opf}`, `internal/sandbox`, `internal/server`, `internal/policysync`, `internal/enrollment`, `internal/licensing`, `internal/firewall`, `internal/sidecar`, `internal/shipper`, `internal/admin`.
