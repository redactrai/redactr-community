package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	TelemetryEnabled bool `json:"telemetry_enabled"`
	FirstRunSeen     bool `json:"first_run_seen"`
}

func Dir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".redactr-community")
}
func path() string { return filepath.Join(Dir(), "config.json") }

// AllowPath is the user allowlist file (extra MITM hosts).
func AllowPath() string { return filepath.Join(Dir(), "allow.txt") }

// ProxyStatePath stores the snapshot of prior system-proxy settings (for revert).
func ProxyStatePath() string { return filepath.Join(Dir(), "proxy-state.json") }

// DaemonPath stores the running daemon's pid/port.
func DaemonPath() string { return filepath.Join(Dir(), "daemon.json") }

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
