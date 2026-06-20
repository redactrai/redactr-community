//go:build darwin

package catrust

import "os/exec"

func installOS(pemPath string) error {
	return exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", pemPath).Run()
}

func removeOS(pemPath string) error {
	cn, err := commonName(pemPath)
	if err != nil {
		return err
	}
	// best-effort; ignore "not found"
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", cn,
		"/Library/Keychains/System.keychain").Run()
	return nil
}

func isTrustedOS(pemPath string) (bool, error) {
	cn, err := commonName(pemPath)
	if err != nil {
		return false, err
	}
	return exec.Command("security", "find-certificate", "-c", cn,
		"/Library/Keychains/System.keychain").Run() == nil, nil
}
