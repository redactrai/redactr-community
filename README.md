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

1. **Get the binary** — download for your OS from the
   **[latest release ⬇](https://github.com/redactrai/redactr-community/releases/latest)**, or build with Go:
   ```
   go install github.com/redactrai/redactr-community/cmd/redactr-community@latest
   ```
2. **Start it** (creates a local CA on first run):
   ```
   redactr-community
   ```
3. **Trust the CA** once — follow the per-OS instructions it prints.
4. **Route your AI tools through it:**
   ```
   export HTTPS_PROXY=http://127.0.0.1:8080
   # or:  redactr-community shell   # opens a subshell with the proxy preset
   ```
   Outbound secrets/PII are now redacted before they leave your machine.

Other commands: `redactr-community ca` (print CA trust steps) · `redactr-community telemetry on|off|status`.

**Downloads:** every tagged release publishes macOS / Linux / Windows binaries on the
**[Releases page](https://github.com/redactrai/redactr-community/releases)**.

## Privacy
Your code, traffic, and redacted values **never** leave your machine. The only thing that
can leave is **opt-in, anonymous** telemetry (off by default): a random session id, app
version, and OS — never content or your IP.

## Telemetry (opt-in, anonymous)
Off by default. Enable with `redactr-community telemetry on`. When on, it sends a heartbeat
every ~10 min containing only: a random session id (rotated daily), the app version, and your
OS. The collector derives country/city from Cloudflare's edge and **discards your IP**. It
never sees your code, traffic, or redacted values. Source: `telemetry/worker/`.

## Build
    make build && make test
