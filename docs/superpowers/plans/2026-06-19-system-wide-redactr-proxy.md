# System-wide Redactr proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the per-`run` proxy into a persistent daemon that OS-trusts its CA, toggles the system proxy, and **only MITM-decrypts allow-listed AI hosts** — so every tool (CLIs like `codex`, GUI IDEs like antigravity) is covered — then rename the command to `redactr`.

**Architecture:** New focused Go packages — `proxy` (allowlist-gated MITM), `systemproxy` (per-OS set/snapshot/revert), `catrust` (per-OS trust install/remove), `daemon` (detached lifecycle), `cli` registry — wired into new commands `enable/disable/status/doctor`. macOS is fully implemented & verified; Windows/Linux are implemented behind build tags to be tested by others.

**Tech Stack:** Go 1.26, `github.com/elazarl/goproxy`, standard library (`os/exec`, `net`, build-tagged per-OS files). TDD for pure logic (allowlist match, proxy-state snapshot, config migration).

**Spec:** `docs/superpowers/specs/2026-06-19-system-wide-redactr-proxy-design.md`

---

## File structure

| File | Responsibility |
|------|----------------|
| `internal/proxy/allowlist.go` (new) | Allowlist type: default AI hosts, suffix/wildcard match, load user `allow.txt` |
| `internal/proxy/allowlist_test.go` (new) | Match logic tests |
| `internal/proxy/proxy.go` (modify) | CONNECT handler MITMs only if host ∈ allowlist, else plain-tunnel |
| `internal/config/config.go` (modify) | `Dir()` → `~/.redactr` + one-time migration; paths for `allow.txt`, `proxy-state.json`, `daemon.json` |
| `internal/systemproxy/systemproxy.go` (new) | `State` snapshot (JSON persist), `Set/Revert` interface |
| `internal/systemproxy/darwin.go|windows.go|linux.go` (new, build-tagged) | per-OS impl |
| `internal/systemproxy/systemproxy_test.go` (new) | snapshot/restore round-trip |
| `internal/catrust/catrust.go` + per-OS files (new) | install/remove CA in OS trust store |
| `internal/daemon/daemon.go` (new) | start detached, pidfile (`daemon.json`), stop, isRunning |
| `internal/cli/registry.go` (new) | tool registry: claude/codex/copilot/antigravity handling |
| `internal/cli/cli.go` (modify) | `ProxyEnv` adds `SSL_CERT_FILE`; registry hookup |
| `cmd/redactr-community/main.go` (modify) | commands `enable/disable/status/doctor`; rename binary in Task 8 |
| `.goreleaser.yaml` (modify, Task 8) | binary/project_name/cask → `redactr` |

Phases are ordered so each is shippable on its own. **Rename (Task 8) is last** — it is the breaking change the user wants tied to the new binary release.

---

## Task 1: Selective MITM by allowlist

**Files:**
- Create: `internal/proxy/allowlist.go`, `internal/proxy/allowlist_test.go`
- Modify: `internal/proxy/proxy.go` (the `HandleConnectFunc`)

- [ ] **Step 1: Write failing tests** in `internal/proxy/allowlist_test.go`

```go
package proxy

import "testing"

func TestAllowlist_Match(t *testing.T) {
	a := NewAllowlist([]string{"api.anthropic.com", "*.githubcopilot.com"})
	cases := map[string]bool{
		"api.anthropic.com:443":        true,
		"api.anthropic.com":            true,
		"copilot.githubcopilot.com:443": true,
		"api.githubcopilot.com:443":    true,
		"example.com:443":              false,
		"evil-api.anthropic.com.evil.com:443": false, // suffix must align on a label boundary
	}
	for host, want := range cases {
		if got := a.Match(host); got != want {
			t.Errorf("Match(%q)=%v want %v", host, got, want)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL** — `go test ./internal/proxy/ -run TestAllowlist` → undefined `NewAllowlist`.

- [ ] **Step 3: Implement** `internal/proxy/allowlist.go`

```go
package proxy

import (
	"bufio"
	"os"
	"strings"
)

// DefaultAllowHosts are the AI-provider hosts MITM-decrypted by default.
// Everything else is tunnelled untouched. Extend via ~/.redactr/allow.txt.
// NOTE: antigravity's exact endpoints are unconfirmed — see plan Task 7 research.
var DefaultAllowHosts = []string{
	"api.anthropic.com",
	"api.openai.com",
	"chatgpt.com",
	"*.githubcopilot.com",
	"copilot-proxy.githubusercontent.com",
	// Google / antigravity (Gemini / Cloud Code) — confirm via capture (Task 7):
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

// hostOnly strips an optional :port.
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
			suffix := p[1:] // ".githubcopilot.com"
			if host == p[2:] || strings.HasSuffix(host, suffix) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// LoadAllowlist returns defaults plus any user entries in path (one host per line).
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
```

- [ ] **Step 4: Run, expect PASS** — `go test ./internal/proxy/ -run TestAllowlist`.

- [ ] **Step 5: Wire into the proxy.** In `internal/proxy/proxy.go`, give `Proxy`/`New` an allowlist and gate the CONNECT handler. Add an `allow *Allowlist` field; accept it in `New` (load via `LoadAllowlist(config.AllowPath())`). Replace:

```go
gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	return goproxy.MitmConnect, host
})
```

with:

```go
gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	if allow.Match(host) {
		return goproxy.MitmConnect, host
	}
	return goproxy.OkConnect, host // plain tunnel — no decryption
})
```

Keep `New`'s existing signature working: add an `allow *Allowlist` parameter (or default to `LoadAllowlist` inside `New` if nil) so existing callers (`newProxy` in main.go) still compile — update that caller to pass `proxy.LoadAllowlist(config.AllowPath())`.

- [ ] **Step 6: Build + full test** — `go build ./... && go test ./...` (all green).
- [ ] **Step 7: Commit** — `git commit -am "feat(proxy): MITM only allow-listed AI hosts; tunnel the rest"`

---

## Task 2: Config dir paths (no rename yet)

**Files:** Modify `internal/config/config.go`

Add path helpers used by later tasks (still under the **current** `~/.redactr-community` dir; the dir rename is Task 8).

- [ ] **Step 1: Add helpers** to `internal/config/config.go`:

```go
// AllowPath is the user allowlist file (extra MITM hosts).
func AllowPath() string { return filepath.Join(Dir(), "allow.txt") }

// ProxyStatePath stores the snapshot of prior system-proxy settings.
func ProxyStatePath() string { return filepath.Join(Dir(), "proxy-state.json") }

// DaemonPath stores the running daemon's pid/port.
func DaemonPath() string { return filepath.Join(Dir(), "daemon.json") }
```

- [ ] **Step 2: Build** — `go build ./...`.
- [ ] **Step 3: Commit** — `git commit -am "feat(config): paths for allowlist, proxy-state, daemon"`

---

## Task 3: System-proxy package (snapshot/set/revert)

**Files:**
- Create: `internal/systemproxy/systemproxy.go`, `darwin.go`, `windows.go`, `linux.go`, `systemproxy_test.go`

**Design:** A `State` is an opaque per-OS snapshot persisted as JSON so we can revert even after a crash/restart. Interface:

```go
package systemproxy

// Set routes the machine's HTTP/HTTPS through host:port, after saving the prior
// state to statePath. Idempotent. Returns error; on error it must not leave a
// partial change (best effort revert).
func Set(host string, port int, statePath string) error

// Revert restores the state saved in statePath, then removes the file. Safe to
// call when nothing was set (no-op).
func Revert(statePath string) error

// IsSet reports whether the system proxy currently points at host:port.
func IsSet(host string, port int) (bool, error)
```

- [ ] **Step 1: TDD the pure round-trip** in `systemproxy_test.go` — the JSON persistence helper (`saveState`/`loadState`) round-trips a `State` struct. (Per-OS network calls are not unit-tested; covered by macOS manual verification.)

```go
package systemproxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "proxy-state.json")
	in := &state{Services: []serviceState{{Name: "Wi-Fi", HTTPSEnabled: false, HTTPSHost: "", HTTPSPort: 0}}}
	if err := saveState(p, in); err != nil { t.Fatal(err) }
	out, err := loadState(p)
	if err != nil { t.Fatal(err) }
	if len(out.Services) != 1 || out.Services[0].Name != "Wi-Fi" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	_ = os.Remove(p)
}
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement `systemproxy.go`** (shared types + JSON persist + dispatch to per-OS `setOS`/`revertOS`/`isSetOS`):

```go
package systemproxy

import (
	"encoding/json"
	"os"
)

type serviceState struct {
	Name         string `json:"name"`
	HTTPSEnabled bool   `json:"https_enabled"`
	HTTPSHost    string `json:"https_host"`
	HTTPSPort    int    `json:"https_port"`
	HTTPEnabled  bool   `json:"http_enabled"`
	HTTPHost     string `json:"http_host"`
	HTTPPort     int    `json:"http_port"`
}

type state struct {
	Services []serviceState `json:"services"` // macOS
	Raw      map[string]string `json:"raw,omitempty"` // windows/linux key/vals
}

func saveState(path string, s *state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil { return err }
	return os.WriteFile(path, b, 0o600)
}

func loadState(path string) (*state, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var s state
	if err := json.Unmarshal(b, &s); err != nil { return nil, err }
	return &s, nil
}

func Set(host string, port int, statePath string) error    { return setOS(host, port, statePath) }
func Revert(statePath string) error                         { return revertOS(statePath) }
func IsSet(host string, port int) (bool, error)             { return isSetOS(host, port) }
```

- [ ] **Step 4: Run, expect PASS** (`go test ./internal/systemproxy/`).

- [ ] **Step 5: Implement `darwin.go`** (`//go:build darwin`) — the **fully-verified** path. Uses `networksetup`:
  - Enumerate services: `networksetup -listallnetworkservices` (skip the `*` disabled prefix + the header line).
  - For each: read current via `networksetup -getsecurewebproxy "<svc>"` and `-getwebproxy`, parse `Enabled: Yes/No`, `Server:`, `Port:` into `serviceState`. Save all to `statePath` (only if the file doesn't already exist, to avoid clobbering a good snapshot with our own proxy).
  - Set: `networksetup -setsecurewebproxy "<svc>" <host> <port>` + `-setwebproxy …` + `-setproxybypassdomains "<svc>" localhost 127.0.0.1 ::1 *.local 169.254/16`.
  - `revertOS`: load state; for each service restore prior host/port and enabled flag (`-setsecurewebproxystate "<svc>" off` if it was off, else re-set saved host/port); delete `statePath`. If `statePath` missing → no-op.
  - `isSetOS`: true if any service's secure web proxy == host:port and enabled.
  - Implement exact parsing with a small helper; commands run via `exec.Command`.

- [ ] **Step 6: Implement `windows.go`** (`//go:build windows`) per spec: registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` — snapshot `ProxyEnable`, `ProxyServer`, `ProxyOverride` into `state.Raw`; set `ProxyServer=host:port`, `ProxyEnable=1`, `ProxyOverride="localhost;127.0.0.1;<local>"`; broadcast `WM_SETTINGCHANGE`/`InternetSetOption(INTERNET_OPTION_SETTINGS_CHANGED)` via `golang.org/x/sys/windows` or `rundll32`. Revert restores saved values. **Compiles but verified by other testers.**

- [ ] **Step 7: Implement `linux.go`** (`//go:build linux`) per spec: GNOME via `gsettings set org.gnome.system.proxy mode 'manual'` + `org.gnome.system.proxy.https host/port` (snapshot prior `mode`/host/port into `state.Raw`); revert restores. Document non-GNOME limitation in a comment. **Compiles but verified by others.**

- [ ] **Step 8: Build all + test** — `go build ./... && go test ./...` and `GOOS=windows go build ./... && GOOS=linux go build ./...` (cross-compile to prove the tagged files compile).
- [ ] **Step 9: Commit** — `git commit -am "feat(systemproxy): per-OS set/snapshot/revert (macOS verified; win/linux specced)"`

---

## Task 4: CA OS-trust package

**Files:** Create `internal/catrust/catrust.go` + `darwin.go`/`windows.go`/`linux.go`.

Interface:

```go
package catrust
// Install adds the CA at pemPath to the OS trust store (may prompt for sudo/admin).
func Install(pemPath string) error
// Remove removes it (by the CA's common name / sha). No-op if absent.
func Remove(pemPath string) error
// IsTrusted reports whether the CA is present in the OS trust store.
func IsTrusted(pemPath string) (bool, error)
```

- [ ] **Step 1: darwin.go** (`//go:build darwin`, verified):
  - Install: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <pemPath>`.
  - Remove: `sudo security delete-certificate -c "<CN>"` (parse CN from the cert) or `security remove-trusted-cert -d <pemPath>`.
  - IsTrusted: `security find-certificate -c "<CN>" /Library/Keychains/System.keychain` exit 0.
  - Parse the CA CN by loading the PEM with `crypto/x509` (`cert.Subject.CommonName`).
- [ ] **Step 2: windows.go** (`//go:build windows`): `certutil -addstore -f Root <pem>` / `certutil -delstore Root "<CN>"` / `certutil -verifystore Root "<CN>"`. Compiles; tested by others.
- [ ] **Step 3: linux.go** (`//go:build linux`): copy to `/usr/local/share/ca-certificates/redactr.crt` + `sudo update-ca-certificates`; remove + update to uninstall. Compiles; tested by others.
- [ ] **Step 4: Build + cross-compile** as Task 3 Step 8.
- [ ] **Step 5: Commit** — `git commit -am "feat(catrust): per-OS CA trust install/remove (macOS verified)"`

---

## Task 5: Daemon lifecycle

**Files:** Create `internal/daemon/daemon.go`.

Responsibilities: start the proxy **detached** from the terminal, write `daemon.json` (`{pid,port}`), report running status, and stop by pid.

- [ ] **Step 1: Implement** start/stop/isRunning. Start re-execs the current binary with a hidden `__daemon` subcommand via `exec.Command`, `cmd.SysProcAttr` set to detach (`Setsid: true` on unix), stdout/stderr → `proxy.log`; parent writes `daemon.json` after confirming the port is listening (dial loop, 3s). `IsRunning()` reads `daemon.json`, checks the pid is alive (`os.FindProcess`+signal 0) AND the port answers. `Stop()` sends SIGTERM to the pid, waits, removes `daemon.json`.
- [ ] **Step 2: Hidden `__daemon` handler** in `main.go`: builds the proxy (`newProxy`), `Start(8080)`, installs SIGINT/SIGTERM handler that calls `systemproxy.Revert(config.ProxyStatePath())` then exits, and blocks.
- [ ] **Step 3: Test** — manual on macOS: start, confirm `daemon.json`, `lsof -i:8080`, stop reverts. Unit-test the `daemon.json` read/write helper.
- [ ] **Step 4: Commit** — `git commit -am "feat(daemon): detached proxy lifecycle with pidfile"`

---

## Task 6: Commands `enable` / `disable` / `status` / `doctor`

**Files:** Modify `cmd/redactr-community/main.go`.

- [ ] **Step 1:** `enable [--login]`: ensure CA exists → `catrust.Install` (if not trusted) → `daemon.Start` → `systemproxy.Set(127.0.0.1, 8080, ProxyStatePath())`. Print clear status + "all AI tools (terminal and GUI) are now protected." `--login` installs the auto-start unit (macOS launchd plist write + `launchctl load`; win/linux specced).
- [ ] **Step 2:** `disable [--untrust]`: `systemproxy.Revert` → `daemon.Stop` → (if `--untrust`) `catrust.Remove`. Idempotent.
- [ ] **Step 3:** `status`: print daemon running?, CA trusted?, system proxy set?, with a **stale-state guard**: if proxy is set but daemon is down, warn loudly and offer `redactr disable` to restore internet.
- [ ] **Step 4:** `doctor`: everything in `status` PLUS a live probe — for each default allow host, issue a HEAD/GET through the local proxy and report whether `X-Redactr-Status` came back (proves interception). Summarize per-tool readiness (claude/codex/antigravity).
- [ ] **Step 5:** Commit — `git commit -am "feat(cli): enable/disable/status/doctor commands"`

---

## Task 7: Tool registry + codex/antigravity + antigravity endpoint research

**Files:** Create `internal/cli/registry.go`; modify `internal/cli/cli.go`.

- [ ] **Step 1:** `ProxyEnv` also sets `SSL_CERT_FILE=<caPath>` and `SSL_CERT_DIR` (helps Rust/reqwest builds that read them) in addition to the existing vars.
- [ ] **Step 2:** Registry maps tool → behavior: `claude`,`codex`,`copilot` = CLI (run with env); `antigravity`,`cursor` = GUI (just launch; rely on the daemon's system proxy). Unknown = generic CLI env. `run` consults it.
- [ ] **Step 3 (RESEARCH — required):** Confirm antigravity's real API hosts. Method: on a machine with antigravity, run `redactr enable` then `redactr doctor`, and/or watch `~/.redactr/proxy.log` while using antigravity, to see which `*.googleapis.com` (or other) hosts it hits. Add the confirmed hosts to `DefaultAllowHosts` (Task 1) via a follow-up commit. Until confirmed, ship the best-guess Google hosts already in defaults + document in README that `redactr allow <host>` covers gaps. (This step is handed to a tester per the OS plan; record the result here.)
- [ ] **Step 4:** Tests for registry classification; build+test.
- [ ] **Step 5:** Commit — `git commit -am "feat(cli): tool registry + codex cert env; antigravity via system proxy"`

---

## Task 8: Rename `redactr-community` → `redactr` (breaking; do last)

**Files:** `.goreleaser.yaml`, `cmd/redactr-community/` (binary name), `internal/config/config.go` (Dir), README, all `--help`/usage strings, telemetry user-agent.

- [ ] **Step 1:** `config.Dir()` → `~/.redactr`, with one-time migration: if `~/.redactr` absent and `~/.redactr-community` exists, `os.Rename` it. Add a unit test for the migration decision (using temp `$HOME`).
- [ ] **Step 2:** GoReleaser: `project_name: redactr`, `builds[].binary: redactr`, `homebrew_casks[].name: redactr`. (Repo + module path stay `redactr-community` per spec — out of scope to rename.)
- [ ] **Step 3:** Replace `redactr-community` in all usage/help/README strings with `redactr`. (Site is updated separately when the binary ships.)
- [ ] **Step 4:** Build + test + `goreleaser release --snapshot --clean` to confirm the artifact is named `redactr`.
- [ ] **Step 5:** Commit — `git commit -am "feat!: rename command redactr-community -> redactr (config dir migrates)"`

---

## Self-review notes
- **Spec coverage:** daemon (T5), system proxy (T3), selective MITM (T1), CA trust (T4), commands+doctor (T6), tool registry/codex/antigravity (T7), rename+edition-dir (T8), config layout (T2). All spec sections mapped.
- **Edition resolution** (enterprise-first `redactr` on PATH) is an enterprise-packaging concern (formula `conflicts_with`), noted in spec §1 — no community code task; documented, not built here.
- **Verification:** macOS manual (T3/T4/T5/T6 steps) + `doctor`; Windows/Linux compile via cross-build (T3 S8) and hand to testers.
- **Biggest risks called out in-task:** dead-proxy→no-internet (T5 signal-revert + T6 status stale-guard + `--login` autorestart); antigravity endpoints (T7 research).
