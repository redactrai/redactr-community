package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/redactrai/redactr-community/internal/config"
)

func TelemetryBanner() string {
	return `── redactr ───────────────────────────────────────────────────
 Anonymous, opt-in telemetry is OFF by default.
 If you enable it, we send only a random session id, the app
 version, and your OS — never your code, traffic, redacted
 values, or IP. It helps us see how many people use the tool.
 Enable:  redactr telemetry on
 Status:  redactr telemetry status
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

// ProxyEnv returns the environment additions that route a child process's HTTPS
// traffic through the local proxy and let common runtimes trust the local CA.
func ProxyEnv(addr, caPath string) []string {
	return []string{
		"HTTPS_PROXY=" + addr,
		"HTTP_PROXY=" + addr,
		"NODE_EXTRA_CA_CERTS=" + caPath, // Node-based tools (e.g. Claude Code) trust the local CA
		"SSL_CERT_FILE=" + caPath,       // Rust/reqwest (e.g. codex) and others read this
		"SSL_CERT_DIR=",                 // empty -> force use of SSL_CERT_FILE only
	}
}

// SetTelemetry persists the consent flag.
func SetTelemetry(on bool) error {
	c := config.Load()
	c.TelemetryEnabled = on
	return config.Save(c)
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
