package telemetry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

type Client struct {
	Enabled  bool
	Endpoint string
	Version  string
	Interval time.Duration
	session  string
	http     *http.Client
}

func newSession() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// beat sends a single anonymous heartbeat. No-op when disabled.
func (c *Client) beat() {
	if !c.Enabled {
		return
	}
	if c.session == "" {
		c.session = newSession()
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 5 * time.Second}
	}
	payload := map[string]string{
		"session": c.session,
		"version": c.Version,
		"os":      runtime.GOOS,
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// Run rotates the session each ~24h and beats on Interval until stop is closed.
func (c *Client) Run(stop <-chan struct{}) {
	if !c.Enabled {
		return
	}
	c.beat()
	t := time.NewTicker(c.Interval)
	rot := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	defer rot.Stop()
	for {
		select {
		case <-stop:
			return
		case <-rot.C:
			c.session = newSession()
		case <-t.C:
			c.beat()
		}
	}
}
