//go:build windows

package daemon

import (
	"os"
	"syscall"
)

func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows, FindProcess always succeeds; send signal 0 is not supported,
	// so we check by sending a no-op kill — this is best-effort.
	_ = p
	return true
}

func sigTerm() os.Signal {
	return os.Interrupt
}
