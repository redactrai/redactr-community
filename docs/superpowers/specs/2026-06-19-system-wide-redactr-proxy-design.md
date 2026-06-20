# System-wide Redactr proxy — daemon + selective MITM + CLI/GUI coverage

**Date:** 2026-06-19
**Status:** Design approved (brainstorm) — pending spec review → implementation plan

## Goal

Make Redactr protect **every** AI coding tool on a machine — terminal CLIs (`claude`, `codex`, …) *and* GUI IDEs (Google **antigravity**, Cursor, …) — without per-tool wiring. Do it by turning the proxy into a **persistent background daemon** that flips the **system proxy** on, trusts its CA at the OS level, and **only decrypts allow-listed AI hosts** (everything else is tunnelled untouched). Also rename the user-facing command to **`redactr`**.

## Background / current state

Today (`redactr-community`):
- Transient proxy started per `run`/`shell`; injects `HTTPS_PROXY`/`HTTP_PROXY`/`NODE_EXTRA_CA_CERTS` into a child process only.
- `OnRequest().HandleConnectFunc` returns `MitmConnect` for **all** hosts (decrypts everything that flows through it).
- Relies on the user manually trusting the CA; nothing sets the system proxy. GUI apps and Rust CLIs that don't read those env vars are **not** protected.

This covers `claude` (Node, reads the env + `NODE_EXTRA_CA_CERTS`) but does **not** reliably cover `codex` (Rust/reqwest: honors `HTTPS_PROXY` but trusts certs via the OS store, not `NODE_EXTRA_CA_CERTS`) or `antigravity` (Electron GUI: ignores those env vars; uses the system proxy + OS cert store).

## Decisions (from brainstorm)

1. **Scope:** cover CLIs *and* GUI IDEs together.
2. **Lifecycle:** a persistent background **daemon** (start once / auto-start), not transient per-`run`.
3. **GUI routing:** **system-proxy toggle** (macOS/Windows/Linux) while the daemon is on; revert when off.
4. **MITM scope:** **selective** — decrypt only allow-listed AI hosts; tunnel all other TLS untouched.
5. **Command rename:** user-facing command becomes **`redactr`** (both editions). A single `redactr` on PATH resolves **enterprise-first, else community**.
6. **OS:** implement all three (macOS/Windows/Linux) up front; **verify on macOS only** for now — Windows/Linux handed to others to test.

## Architecture overview

```
                         ┌─────────────────────────────────────────┐
  any tool (CLI or GUI)  │  redactr daemon (loopback :8080)         │
  ───HTTPS via system────▶  CONNECT host ─┬─ host ∈ allowlist? ──▶ MITM → redact → upstream
        proxy            │                └─ else ─────────────▶ plain tunnel (no decrypt)
                         └─────────────────────────────────────────┘
   CA trusted at OS level · system proxy set while daemon ON · reverted on OFF/crash
```

## Components

### 1. Command surface + rename to `redactr`
- Binary/command renamed `redactr-community` → **`redactr`** (GoReleaser `binary`/`project_name`, Homebrew cask name → `redactr`, so `brew install redactrai/tap/redactr`).
- Config/data dir `~/.redactr-community/` → **`~/.redactr/`** (one-time migration: if old dir exists and new doesn't, move it; else create new).
- All help text, examples, telemetry, README, and site install copy updated to `redactr`.
- **Edition resolution:** community ships `redactr`; enterprise ships its own `redactr` that supersedes (install precedence / the enterprise formula `conflicts_with` community). A single `redactr` on PATH = enterprise if installed, else community. (Enterprise packaging detail; community side just names the binary `redactr`.)
- Commands:
  - `redactr enable [--login]` — ensure CA generated + OS-trusted, start daemon, set system proxy; `--login` installs an auto-start service.
  - `redactr disable [--untrust]` — stop daemon, **revert system proxy**, optionally remove CA from OS trust.
  - `redactr status` / `redactr doctor` — health + live verification (see §6).
  - `redactr run <cmd>` / `redactr shell` — kept as convenience for CLIs (and to set codex cert env). GUIs need no `run` once the daemon is on.
  - existing `start` (foreground), `ca`, `telemetry` retained (`start` documented as the foreground/debug variant of the daemon).

### 2. Persistent daemon
- Runs the proxy on `127.0.0.1:8080` (loopback only), detached from the terminal.
- Records a PID/state file in `~/.redactr/daemon.json` (pid, port, proxy-set flag).
- `--login` installs an OS auto-start unit: macOS launchd LaunchAgent, Windows service/Scheduled Task, Linux systemd **user** unit. The unit also **auto-restarts** the daemon if it dies (mitigates the dead-proxy hazard, see §9).

### 3. System-proxy integration (per-OS) + safety
- **Set on enable / revert on disable**, per active network service, with a bypass list (`localhost, 127.0.0.1, ::1, *.local`, link-local).
  - macOS: `networksetup -setwebproxy / -setsecurewebproxy / -setproxybypassdomains` over each active service; revert restores prior on/off + host/port.
  - Windows: `HKCU\…\Internet Settings` `ProxyServer`/`ProxyEnable`/`ProxyOverride` + WinINet change notify.
  - Linux: GNOME `gsettings org.gnome.system.proxy` (+ document that non-GNOME desktops vary); env fallback for shells.
- **Safety (critical):** before changing anything, snapshot prior proxy state to `~/.redactr/proxy-state.json`. Restore it on `disable`, on `SIGINT`/`SIGTERM`, and **auto-repair**: `status`/`enable` detect "system proxy points at us but daemon is down" and offer/auto-revert. Rationale in §9.

### 4. Selective MITM by allowlist
- Replace blanket `MitmConnect` with: `host ∈ allowlist ? MitmConnect : OkConnect` (plain CONNECT tunnel — no decryption).
- **Allowlist** = built-in defaults + user file `~/.redactr/allow.txt` (suffix/wildcard match). `redactr allow <host>` appends.
- Built-in defaults (confirm exact hosts during implementation — see §10):
  - Anthropic: `api.anthropic.com`
  - OpenAI / codex: `api.openai.com` (+ any `chatgpt.com` backend codex uses)
  - GitHub Copilot: `*.githubcopilot.com`, `copilot-proxy.githubusercontent.com`
  - Google / **antigravity**: its Gemini/Cloud-Code backend (likely `*.googleapis.com` — **research item, must confirm by capturing antigravity traffic**)

### 5. OS CA trust
- `enable` generates the CA (existing) and installs it into the **OS trust store** (one-time `sudo`/admin):
  - macOS: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`
  - Windows: `certutil -addstore -f Root`
  - Linux: copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates`
- `disable --untrust` removes it. `NODE_EXTRA_CA_CERTS` retained in `run` env as belt-and-suspenders for Node CLIs.

### 6. `run`/`shell` + tool registry + `doctor`
- Tool registry maps known tools to handling: `claude` (env ok), `codex` (set `SSL_CERT_FILE` to the CA in `run` env; verify reqwest trust), `copilot`, `antigravity` (GUI → just launch; relies on system proxy). Unknown → generic env injection.
- `redactr doctor` verifies and reports per concern: daemon listening; CA present in OS trust; system proxy set + bypass correct; and a **live probe** to each allowlisted host checking for the `X-Redactr-Status` response header. This is how codex/antigravity coverage is *verified*, not assumed.

## Config / data layout (`~/.redactr/`)
- `ca.pem`, `ca.key` (0600) — unchanged, new dir.
- `daemon.json` — pid, port, proxy-set flag.
- `proxy-state.json` — snapshot of prior system-proxy settings for safe revert.
- `allow.txt` — user allowlist additions.
- `proxy.log` — daemon log (already routed here).

## Security & threat model
- **Selective MITM** ⇒ only AI hosts are decrypted; bank/email/OS-update traffic is **tunnelled untouched** → preserves privacy and won't break cert-pinned apps.
- Proxy binds **loopback only**; CA key stays local `0600`.
- OS-trusting a local root CA is the sensitive action — documented plainly, with a clean one-command `disable --untrust` removal.
- **Biggest operational hazard:** the system proxy points at the daemon; if the daemon dies, *all* internet breaks (can't fail-open a system proxy). Mitigations: snapshot+restore, signal handlers, `status` auto-repair, and the auto-restart launch unit. This safety machinery is first-class scope, not optional.

## Testing strategy
- **macOS: full verification** — `enable`/`disable` set+revert system proxy; CA trust install/remove; `claude`, `codex`, and **antigravity** each show `X-Redactr-Status` via `doctor`; crash-revert leaves working internet.
- **Windows/Linux: implemented + unit-tested**, behavior specced precisely; **manual end-to-end handed to other testers**. Code paths guarded so macOS verification isn't blocked by them.
- Unit tests: allowlist matching (suffix/wildcard, MITM-vs-tunnel decision), proxy-state snapshot/restore round-trip, config-dir migration, tool-registry env construction.

## Open research items / risks
1. **antigravity's actual API endpoints** — must capture to populate the allowlist; without it antigravity isn't covered. (#1 risk.)
2. **codex TLS trust** — confirm OS-trust alone suffices for reqwest, or whether `SSL_CERT_FILE` is required.
3. Per-OS system-proxy + CA-trust exact commands and their revert (esp. Windows notify, multi–network-service macOS).
4. Confirm antigravity (Chromium) uses the macOS system proxy by default (expected yes).

## Out of scope
- Renaming the GitHub repo / Go module path (keep `redactr-community` repo + module to avoid breaking URLs; only the **command/binary/cask/config-dir** rename to `redactr`).
- Enterprise-specific ML detection and signed-policy push of the allowlist (enterprise inherits this infra; its additions are separate work).
- Per-app config and Electron-launch-flag routing (rejected in favor of system proxy).
