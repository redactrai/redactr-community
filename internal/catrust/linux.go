//go:build linux

package catrust

import (
	"os"
	"os/exec"
)

const linuxCACertPath = "/usr/local/share/ca-certificates/redactr.crt"

func installOS(pemPath string) error {
	if err := exec.Command("sudo", "cp", pemPath, linuxCACertPath).Run(); err != nil {
		return err
	}
	return exec.Command("sudo", "update-ca-certificates").Run()
}

func removeOS(pemPath string) error {
	if err := exec.Command("sudo", "rm", "-f", linuxCACertPath).Run(); err != nil {
		return err
	}
	return exec.Command("sudo", "update-ca-certificates", "--fresh").Run()
}

func isTrustedOS(pemPath string) (bool, error) {
	_, err := os.Stat(linuxCACertPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
