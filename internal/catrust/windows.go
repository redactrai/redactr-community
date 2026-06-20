//go:build windows

package catrust

import "os/exec"

func installOS(pemPath string) error {
	return exec.Command("certutil", "-addstore", "-f", "Root", pemPath).Run()
}

func removeOS(pemPath string) error {
	cn, err := commonName(pemPath)
	if err != nil {
		return err
	}
	// best-effort; ignore "not found"
	_ = exec.Command("certutil", "-delstore", "Root", cn).Run()
	return nil
}

func isTrustedOS(pemPath string) (bool, error) {
	cn, err := commonName(pemPath)
	if err != nil {
		return false, err
	}
	return exec.Command("certutil", "-verifystore", "Root", cn).Run() == nil, nil
}
