//go:build linux

// Package systemproxy sets and reverts the OS HTTP/HTTPS system proxy.
// NOTE: This implementation targets GNOME desktops via gsettings.
// Non-GNOME desktops (KDE, XFCE, i3, etc.) are not covered and will
// require separate implementations.
package systemproxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func setOS(host string, port int, statePath string) error {
	// Only snapshot if no existing snapshot.
	if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
		snap, err := snapshotGSettings()
		if err != nil {
			return err
		}
		if err := saveState(statePath, snap); err != nil {
			return err
		}
	}

	portStr := strconv.Itoa(port)
	cmds := [][]string{
		{"gsettings", "set", "org.gnome.system.proxy", "mode", "manual"},
		{"gsettings", "set", "org.gnome.system.proxy.https", "host", host},
		{"gsettings", "set", "org.gnome.system.proxy.https", "port", portStr},
		{"gsettings", "set", "org.gnome.system.proxy.http", "host", host},
		{"gsettings", "set", "org.gnome.system.proxy.http", "port", portStr},
	}
	for _, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			return fmt.Errorf("gsettings %s: %w", strings.Join(args[1:], " "), err)
		}
	}
	return nil
}

func revertOS(statePath string) error {
	if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	snap, err := loadState(statePath)
	if err != nil {
		return err
	}

	raw := snap.Raw
	if raw == nil {
		raw = map[string]string{}
	}

	restore := func(schema, key, val string) error {
		if err := exec.Command("gsettings", "set", schema, key, val).Run(); err != nil {
			return fmt.Errorf("gsettings set %s %s: %w", schema, key, err)
		}
		return nil
	}

	var firstErr error
	set := func(schema, key, fallback string) {
		val := fallback
		if v, ok := raw[schema+"."+key]; ok {
			val = v
		}
		if err := restore(schema, key, val); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	set("org.gnome.system.proxy", "mode", "none")
	set("org.gnome.system.proxy.https", "host", "")
	set("org.gnome.system.proxy.https", "port", "0")
	set("org.gnome.system.proxy.http", "host", "")
	set("org.gnome.system.proxy.http", "port", "0")

	os.Remove(statePath) //nolint:errcheck
	return firstErr
}

func isSetOS(host string, port int) (bool, error) {
	mode, err := gsettingsGet("org.gnome.system.proxy", "mode")
	if err != nil || strings.TrimSpace(mode) != "'manual'" {
		return false, err
	}
	h, err := gsettingsGet("org.gnome.system.proxy.https", "host")
	if err != nil {
		return false, err
	}
	p, err := gsettingsGet("org.gnome.system.proxy.https", "port")
	if err != nil {
		return false, err
	}
	h = strings.Trim(strings.TrimSpace(h), "'")
	pInt, err := strconv.Atoi(strings.TrimSpace(p))
	if err != nil {
		return false, nil
	}
	return h == host && pInt == port, nil
}

func gsettingsGet(schema, key string) (string, error) {
	out, err := exec.Command("gsettings", "get", schema, key).Output()
	if err != nil {
		return "", fmt.Errorf("gsettings get %s %s: %w", schema, key, err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// snapshotGSettings reads the current GNOME proxy settings.
func snapshotGSettings() (*state, error) {
	raw := make(map[string]string)
	keys := []struct{ schema, key string }{
		{"org.gnome.system.proxy", "mode"},
		{"org.gnome.system.proxy.https", "host"},
		{"org.gnome.system.proxy.https", "port"},
		{"org.gnome.system.proxy.http", "host"},
		{"org.gnome.system.proxy.http", "port"},
	}
	for _, kk := range keys {
		val, err := gsettingsGet(kk.schema, kk.key)
		if err != nil {
			return nil, err
		}
		raw[kk.schema+"."+kk.key] = val
	}
	return &state{Raw: raw}, nil
}
