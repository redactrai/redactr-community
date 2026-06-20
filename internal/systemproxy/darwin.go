//go:build darwin

package systemproxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// listServices returns the active (non-disabled) network service names.
func listServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("networksetup -listallnetworkservices: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var services []string
	for i, line := range lines {
		if i == 0 {
			// First line is the header: "An asterisk (*) denotes that a network service is disabled."
			continue
		}
		if strings.HasPrefix(line, "*") {
			// Disabled service
			continue
		}
		name := strings.TrimSpace(line)
		if name != "" {
			services = append(services, name)
		}
	}
	return services, nil
}

// parseProxyOutput parses the output of networksetup -getsecurewebproxy / -getwebproxy.
// Returns enabled, host, port.
func parseProxyOutput(output string) (enabled bool, host string, port int) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "Enabled:"); ok {
			enabled = strings.TrimSpace(after) == "Yes"
		} else if after, ok := strings.CutPrefix(line, "Server:"); ok {
			host = strings.TrimSpace(after)
		} else if after, ok := strings.CutPrefix(line, "Port:"); ok {
			p, err := strconv.Atoi(strings.TrimSpace(after))
			if err == nil {
				port = p
			}
		}
	}
	return
}

// readServiceState reads the current HTTP and HTTPS proxy settings for a single service.
func readServiceState(svc string) (serviceState, error) {
	ss := serviceState{Name: svc}

	httpsOut, err := exec.Command("networksetup", "-getsecurewebproxy", svc).Output()
	if err != nil {
		return ss, fmt.Errorf("getsecurewebproxy %q: %w", svc, err)
	}
	ss.HTTPSEnabled, ss.HTTPSHost, ss.HTTPSPort = parseProxyOutput(string(httpsOut))

	httpOut, err := exec.Command("networksetup", "-getwebproxy", svc).Output()
	if err != nil {
		return ss, fmt.Errorf("getwebproxy %q: %w", svc, err)
	}
	ss.HTTPEnabled, ss.HTTPHost, ss.HTTPPort = parseProxyOutput(string(httpOut))

	return ss, nil
}

func setOS(host string, port int, statePath string) error {
	// Only snapshot if no existing snapshot (so a second Set doesn't overwrite real prior state).
	if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
		svcs, err := listServices()
		if err != nil {
			return err
		}
		var snap state
		for _, svc := range svcs {
			ss, err := readServiceState(svc)
			if err != nil {
				return err
			}
			snap.Services = append(snap.Services, ss)
		}
		if err := saveState(statePath, &snap); err != nil {
			return err
		}
	}

	svcs, err := listServices()
	if err != nil {
		return err
	}
	portStr := strconv.Itoa(port)
	for _, svc := range svcs {
		if err := exec.Command("networksetup", "-setsecurewebproxy", svc, host, portStr).Run(); err != nil {
			return fmt.Errorf("setsecurewebproxy %q: %w", svc, err)
		}
		if err := exec.Command("networksetup", "-setwebproxy", svc, host, portStr).Run(); err != nil {
			return fmt.Errorf("setwebproxy %q: %w", svc, err)
		}
		if err := exec.Command("networksetup", "-setproxybypassdomains", svc,
			"localhost", "127.0.0.1", "::1", "*.local", "169.254/16").Run(); err != nil {
			return fmt.Errorf("setproxybypassdomains %q: %w", svc, err)
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

	var firstErr error
	for _, ss := range snap.Services {
		svc := ss.Name
		// Revert HTTPS
		if ss.HTTPSEnabled && ss.HTTPSHost != "" {
			portStr := strconv.Itoa(ss.HTTPSPort)
			if err := exec.Command("networksetup", "-setsecurewebproxy", svc, ss.HTTPSHost, portStr).Run(); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("setsecurewebproxy %q: %w", svc, err)
				}
			}
		} else {
			if err := exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run(); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("setsecurewebproxystate %q off: %w", svc, err)
				}
			}
		}
		// Revert HTTP
		if ss.HTTPEnabled && ss.HTTPHost != "" {
			portStr := strconv.Itoa(ss.HTTPPort)
			if err := exec.Command("networksetup", "-setwebproxy", svc, ss.HTTPHost, portStr).Run(); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("setwebproxy %q: %w", svc, err)
				}
			}
		} else {
			if err := exec.Command("networksetup", "-setwebproxystate", svc, "off").Run(); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("setwebproxystate %q off: %w", svc, err)
				}
			}
		}
	}

	// Always remove the state file, even if some services failed to revert.
	os.Remove(statePath) //nolint:errcheck
	return firstErr
}

func isSetOS(host string, port int) (bool, error) {
	svcs, err := listServices()
	if err != nil {
		return false, err
	}
	for _, svc := range svcs {
		out, err := exec.Command("networksetup", "-getsecurewebproxy", svc).Output()
		if err != nil {
			continue
		}
		en, h, p := parseProxyOutput(string(out))
		if en && h == host && p == port {
			return true, nil
		}
	}
	return false, nil
}
