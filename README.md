<p align="center"><img src="assets/logo.svg" width="88" alt="redactr-community logo" /></p>

# redactr-community

[![CI](https://github.com/redactrai/redactr-community/actions/workflows/ci.yml/badge.svg)](https://github.com/redactrai/redactr-community/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-AGPL%20v3-A42E2B?logo=gnu&logoColor=white)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen?logo=go&logoColor=white)
![Telemetry](https://img.shields.io/badge/telemetry-opt--in%20%C2%B7%20anonymous-46E5A0?logoColor=white)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4)

Free, source-available (AGPL-3.0) **regex-only** redaction proxy. Runs locally and strips
secrets/PII (API keys, emails, SSNs, connection strings, …) out of your AI tools' HTTPS
requests before they leave your machine.

Part of [Redactr](https://redactrai.com). The community edition is regex-only; the full
product adds statistical + ML detection, agent sandboxing, and a team control plane.

## Quick start

Install with Homebrew (macOS):
```bash
brew install redactrai/tap/redactr
```

Run any AI tool through it. This **starts the proxy if it isn't already running**, then launches the
tool in a shell that already has the redaction proxy attached:
```bash
redactr run claude        # also: codex, copilot, or any command
```
On first run it prints a one-time `sudo` line to trust the local CA. After that, secrets/PII in the
tool's outbound HTTPS requests are redacted before they ever leave your machine.

Other commands:
- `redactr shell` — open an interactive shell with the proxy attached
- `redactr start` — run the proxy in the foreground
- `redactr ca` — print CA-trust instructions
- `redactr enable` — trust the CA, start the daemon, and set the system proxy
- `redactr disable` — revert the system proxy and stop the daemon
- `redactr status` — show daemon, CA trust, and system proxy state
- `redactr doctor` — run status checks plus a live interception probe
- `redactr allow <host>` — add a host to the MITM allowlist
- `redactr telemetry on|off|status`

On **Windows or Linux** (or to install manually on macOS), grab a binary for your OS and chip from the **[Releases page](https://github.com/redactrai/redactr-community/releases)** — `.zip` for Windows (x64), `.tar.gz` for Linux (x64/arm64) and macOS. Each release ships SHA-256 checksums.

## Privacy
Your code, traffic, and redacted values **never** leave your machine. The only thing that
can leave is **opt-in, anonymous** telemetry (off by default): a random session id, app
version, and OS — never content or your IP.

## Telemetry (opt-in, anonymous)
Off by default. Enable with `redactr telemetry on`. When on, it sends a heartbeat
every ~10 min containing only: a random session id (rotated daily), the app version, and your
OS. The collector derives country/city from Cloudflare's edge and **discards your IP**. It
never sees your code, traffic, or redacted values. Source: `telemetry/worker/`.

## Build
    make build && make test
