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
