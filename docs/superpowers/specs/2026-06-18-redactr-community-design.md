# redactr-community — Design Spec

**Date:** 2026-06-18
**Repo:** `github.com/redactrai/redactr-community`
**Status:** Approved design → ready for implementation plan
**Order:** Build the binary and verify it works **first**; the site freemium update is a separate, later cycle.

---

## 1. Goal

A free, source-available, **regex-only** redaction proxy — the top-of-funnel "community edition" of Redactr. A developer runs one binary, points their AI tools' HTTPS traffic through it, and secrets/PII are redacted locally before leaving the machine. It exists to drive adoption and feed the enterprise funnel; the paid product's moat (statistical/ML detection, sandboxing, fleet control-plane, audit) is deliberately **not** included.

## 2. Scope

**In scope (this cycle — the binary):**
- Standalone Go binary `redactr-community`: a local HTTPS MITM proxy that redacts using regex patterns only.
- Local CA generation + trust workflow.
- Opt-in, anonymized telemetry (active-user count + coarse geo) and its collector.
- Cross-platform builds + GitHub Releases.
- Tests + a verified end-to-end manual run.

**Out of scope (later cycle):**
- Site freemium changes (Free email-gated download, Enterprise "book a call"). The site links to `redactr-community` releases once they exist.
- Any paid features (see §5 exclusions).

## 3. License

**AGPL-3.0.** Source is public (trust + verifiability — which also backs the "we never see your data" claim, since anyone can read that the tool only phones home for opt-in telemetry). Copyleft deters proprietary forks and SaaS competitors building on it.

## 4. Architecture

Clean, **standalone** Go module (`module github.com/redactrai/redactr-community`, own `go.mod`). We **copy only** the regex + proxy + CA code from the private repo — never the engine wiring, ML, sandbox, server, or policy. The public repo reveals nothing beyond regex matching and a generic MITM proxy.

Components:
- **`scanner`** — regex detection. Lift `internal/scanner/regex/regex.go` (23 patterns: EMAIL, SSN, CREDIT-CARD, PHONE, AWS-ACCESS-KEY, AWS-SECRET-KEY, GCP-API-KEY, PRIVATE-KEY, JWT, CONNECTION-STRING, GENERIC-SECRET, IP-ADDRESS, IPV6, IBAN, MAC, …) plus the minimal types from `internal/scanner/types.go` (`Finding`, `ScanResult`). Replacement format `[REDACTED-<LABEL>]` (from `internal/redactor/redactor.go`).
- **`proxy`** — HTTPS MITM via `github.com/elazarl/goproxy`. Lift the scan path from `internal/proxy/proxy.go` + `extract.go` (find last user message in JSON) + `rewrite.go` (rebuild body, fix Content-Length). Trim domain/bypass to a simple host filter.
- **`certgen`** — local CA. Lift `internal/certgen/ca.go` (ECDSA P-256 self-signed root, on-demand leaf certs). Pure stdlib.
- **`telemetry`** — opt-in heartbeat client (see §6).
- **`cmd/redactr-community`** — CLI entrypoint.

**Detection-scope decision:** v1 ships the **regex layer only** (`regex.go`). The Presidio port (`presidio.go`) is pattern-based too but adds context-scoring/validation; it is **excluded** from the free tier to keep the line clean (free = regex patterns; paid = the more sophisticated detection + entropy + ML). *Revisit if we want a stronger free tier.*

## 5. Extraction — copy vs. exclude

**Copy (regex + proxy + CA only):**
`internal/scanner/types.go`, `internal/scanner/regex/regex.go`, `internal/redactor/redactor.go`, `internal/proxy/{proxy,extract,rewrite,sni,bypass}.go`, `internal/certgen/ca.go`. Strip the multi-layer `pipeline.go` down to a single regex layer (or inline it).

**Never copy (paid IP / not needed):**
`internal/scanner/{entropy,gliner,opf}/`, `internal/sandbox/`, `internal/server/`, `internal/policysync/`, `internal/enrollment/`, `internal/licensing/`, `internal/firewall/`, `internal/sidecar/`, `internal/shipper/`, `internal/admin/`. Drop deps: bbolt, websocket, go-oidc, sqlite, prometheus.

**Minimal deps:** `github.com/elazarl/goproxy`, `golang.org/x/crypto`, stdlib.

## 6. Telemetry (opt-in, anonymized)

**Default OFF.** On first run, print a clear **banner**: what telemetry is, that it's anonymous, that it helps improve the product, and how to enable it (`redactr-community telemetry on`) / disable (`telemetry off`). Consent stored in a local config file (e.g., `~/.redactr-community/config`). Nothing is sent until explicitly enabled.

**When enabled, the client sends only:** a periodic heartbeat (~every 10 min while running) containing a **random, rotating session ID** (not tied to identity or machine), app version, and OS. **Never** code, traffic, redacted values, IP, hostname, or any user data.

**Coarse location, without the client sending it:** the collector reads **country + city from the Cloudflare edge** (`request.cf.country` / `request.cf.city`) and **discards the IP** — only country/city are stored. No GPS, no IP retention → genuinely anonymous.

**Collector:** a small **Cloudflare Worker** + **Analytics Engine** (time-series), kept **in this public repo** (`telemetry/worker/`) for transparency. Enables queries like "active sessions in the last 15 min, grouped by country/city." "Active" = a heartbeat seen within the last ~15 min.

## 7. CLI / UX

- `redactr-community` (or `… start`) — generate CA if missing, start the local proxy, print the proxy address + one-time CA-trust instructions per OS.
- `redactr-community ca` — print CA path / trust instructions.
- `redactr-community shell` — spawn a subshell with `HTTPS_PROXY`/`HTTP_PROXY` set to the proxy (zero-config usage).
- `redactr-community telemetry on|off|status`.
- First run prints the telemetry banner (§6) and CA-trust guidance.

## 8. Distribution

- Cross-compiled binaries (macOS arm64/amd64, Linux amd64/arm64, Windows amd64) via a `Makefile`/GoReleaser, published to **GitHub Releases**.
- `README.md` (install, CA trust, usage, telemetry/privacy statement), `LICENSE` (AGPL-3.0).
- GitHub Actions CI: build + test on push; release on tag.

## 9. Verification — "make sure it works" (gate before the site)

- **Unit tests:** each regex pattern redacts known positives; false-positive guards (e.g., normal prose, code identifiers) stay untouched; replacement format correct.
- **Proxy tests:** a request body with embedded fake secrets → scanned → forwarded body contains `[REDACTED-*]`, Content-Length corrected.
- **Telemetry tests:** nothing sent when OFF; when ON, payload contains only the allowed fields (no content/IP); collector stores country/city only.
- **Manual end-to-end:** start proxy, trust CA, send a real HTTPS request with fake secrets through it, confirm the destination receives redacted text; verify telemetry silent until opted in, then anonymous heartbeats only.

## 10. Open decisions / assumptions

- **Detection scope:** regex layer only for v1 (Presidio excluded) — see §4. Override if a stronger free tier is wanted.
- **Telemetry storage:** Cloudflare Analytics Engine assumed (fits the existing Cloudflare stack); KV/D1 is a fallback.
- **Heartbeat interval / active window:** 10 min / 15 min — tunable.
- **Config location:** `~/.redactr-community/` — confirm.

## 11. Not changed / preserved

- The private repo is untouched. This is a one-way copy of regex/proxy/CA into a clean public module; the two can diverge safely.
