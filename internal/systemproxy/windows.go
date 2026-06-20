//go:build windows

package systemproxy

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func setOS(host string, port int, statePath string) error {
	// Only snapshot if no existing snapshot.
	if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
		snap, err := snapshotRegistry()
		if err != nil {
			return err
		}
		if err := saveState(statePath, snap); err != nil {
			return err
		}
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	proxyServer := fmt.Sprintf("%s:%d", host, port)
	if err := k.SetStringValue("ProxyServer", proxyServer); err != nil {
		return fmt.Errorf("set ProxyServer: %w", err)
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}
	if err := k.SetStringValue("ProxyOverride", "localhost;127.0.0.1;<local>"); err != nil {
		return fmt.Errorf("set ProxyOverride: %w", err)
	}
	// TODO: broadcast WM_SETTINGCHANGE to notify running applications of proxy change.
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

	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		os.Remove(statePath) //nolint:errcheck
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	raw := snap.Raw
	if raw == nil {
		raw = map[string]string{}
	}

	// Restore ProxyEnable (DWORD)
	if val, ok := raw["ProxyEnable"]; ok {
		n, _ := strconv.ParseUint(val, 10, 32)
		k.SetDWordValue("ProxyEnable", uint32(n)) //nolint:errcheck
	} else {
		k.SetDWordValue("ProxyEnable", 0) //nolint:errcheck
	}

	// Restore ProxyServer (string)
	if val, ok := raw["ProxyServer"]; ok {
		k.SetStringValue("ProxyServer", val) //nolint:errcheck
	} else {
		k.DeleteValue("ProxyServer") //nolint:errcheck
	}

	// Restore ProxyOverride (string)
	if val, ok := raw["ProxyOverride"]; ok {
		k.SetStringValue("ProxyOverride", val) //nolint:errcheck
	} else {
		k.DeleteValue("ProxyOverride") //nolint:errcheck
	}

	// TODO: broadcast WM_SETTINGCHANGE to notify running applications of proxy change.
	os.Remove(statePath) //nolint:errcheck
	return nil
}

func isSetOS(host string, port int) (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return false, fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return false, nil
	}
	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return false, nil
	}
	want := fmt.Sprintf("%s:%d", host, port)
	return server == want, nil
}

// snapshotRegistry reads the current proxy registry values into a state.
func snapshotRegistry() (*state, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	raw := make(map[string]string)

	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		raw["ProxyEnable"] = strconv.FormatUint(v, 10)
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		raw["ProxyServer"] = v
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		raw["ProxyOverride"] = v
	}

	return &state{Raw: raw}, nil
}
