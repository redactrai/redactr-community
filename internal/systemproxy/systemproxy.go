// Package systemproxy sets and reverts the OS HTTP/HTTPS system proxy.
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
	Services []serviceState    `json:"services,omitempty"` // macOS
	Raw      map[string]string `json:"raw,omitempty"`      // windows/linux
}

func saveState(path string, s *state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func loadState(path string) (*state, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Set routes HTTP/HTTPS through host:port, snapshotting prior settings to statePath.
func Set(host string, port int, statePath string) error { return setOS(host, port, statePath) }

// Revert restores the snapshot in statePath then deletes it; no-op if absent.
func Revert(statePath string) error { return revertOS(statePath) }

// IsSet reports whether the system proxy currently points at host:port.
func IsSet(host string, port int) (bool, error) { return isSetOS(host, port) }
