// Package daemon manages a detached background proxy process.
package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/redactrai/redactr-community/internal/config"
)

// Info holds the running daemon's PID and port, serialised to daemon.json.
type Info struct {
	PID  int `json:"pid"`
	Port int `json:"port"`
}

func portAnswers(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// IsRunning reports whether the daemon is up (pidfile present, pid alive, port answering).
func IsRunning() (bool, *Info) {
	b, err := os.ReadFile(config.DaemonPath())
	if err != nil {
		return false, nil
	}
	var i Info
	if json.Unmarshal(b, &i) != nil {
		return false, nil
	}
	if pidAlive(i.PID) && portAnswers(i.Port) {
		return true, &i
	}
	return false, &i
}

// Start launches a detached daemon on port if one isn't already running.
func Start(port int) error {
	if up, _ := IsRunning(); up {
		return nil
	}
	if err := os.MkdirAll(config.Dir(), 0o755); err != nil {
		return err
	}
	logf, err := os.OpenFile(config.Dir()+"/proxy.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(os.Args[0], "__daemon", "--port", strconv.Itoa(port))
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = detachSysProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	// wait for the port to come up
	for i := 0; i < 30; i++ {
		if portAnswers(port) {
			b, _ := json.Marshal(Info{PID: cmd.Process.Pid, Port: port})
			return os.WriteFile(config.DaemonPath(), b, 0o644)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return fmt.Errorf("daemon did not start listening on port %d", port)
}

// Stop terminates the daemon and removes the pidfile.
func Stop() error {
	b, err := os.ReadFile(config.DaemonPath())
	if err != nil {
		return nil // not running
	}
	var i Info
	_ = json.Unmarshal(b, &i)
	if i.PID > 0 {
		if p, err := os.FindProcess(i.PID); err == nil {
			_ = p.Signal(sigTerm())
		}
		for j := 0; j < 30 && pidAlive(i.PID); j++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return os.Remove(config.DaemonPath())
}
