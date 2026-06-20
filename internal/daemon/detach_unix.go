//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func sigTerm() os.Signal {
	return syscall.SIGTERM
}
