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
version, and OS — never content or your IP.

## Telemetry (opt-in, anonymous)
Off by default. Enable with `redactr-community telemetry on`. When on, it sends a heartbeat
every ~10 min containing only: a random session id (rotated daily), the app version, and your
OS. The collector derives country/city from Cloudflare's edge and **discards your IP**. It
never sees your code, traffic, or redacted values. Source: `telemetry/worker/`.

## Build
    make build && make test
