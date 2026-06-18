package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/redactrai/redactr-community/internal/certgen"
	"github.com/redactrai/redactr-community/internal/cli"
	"github.com/redactrai/redactr-community/internal/config"
	"github.com/redactrai/redactr-community/internal/proxy"
	"github.com/redactrai/redactr-community/internal/scanner"
	"github.com/redactrai/redactr-community/internal/telemetry"
)

var version = "dev" // set via -ldflags at release

const telemetryEndpoint = "https://t.redactrai.com/beat"

func caPaths() (string, string) {
	d := config.Dir()
	return filepath.Join(d, "ca.pem"), filepath.Join(d, "ca.key")
}

func main() {
	cmd := "start"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "telemetry":
		handleTelemetry()
	case "ca":
		cert, _ := caPaths()
		fmt.Println(cli.TrustInstructions(cert))
	case "shell":
		runShell()
	case "start":
		runStart()
	default:
		fmt.Println("usage: redactr-community [start|shell|ca|telemetry on|off|status]")
	}
}

func handleTelemetry() {
	arg := ""
	if len(os.Args) > 2 {
		arg = os.Args[2]
	}
	switch arg {
	case "on":
		_ = cli.SetTelemetry(true)
		fmt.Println("telemetry: ON (anonymous)")
	case "off":
		_ = cli.SetTelemetry(false)
		fmt.Println("telemetry: OFF")
	default:
		fmt.Printf("telemetry: %v\n", config.Load().TelemetryEnabled)
	}
}

func newProxy() (*proxy.Proxy, string, string) {
	cert, key := caPaths()
	ca, err := certgen.LoadOrCreateCA(cert, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CA error:", err)
		os.Exit(1)
	}
	s := scanner.New()
	p, err := proxy.New(ca, s.Redact, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		os.Exit(1)
	}
	return p, cert, key
}

func runStart() {
	cli.MaybeShowFirstRun()
	p, cert, _ := newProxy()
	addr, err := p.Start(8080)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		os.Exit(1)
	}
	fmt.Printf("redactr-community proxy listening on %s\n", addr)
	fmt.Println(cli.TrustInstructions(cert))
	fmt.Printf("Then: export HTTPS_PROXY=%s\n", addr)

	stop := make(chan struct{})
	if config.Load().TelemetryEnabled {
		tc := &telemetry.Client{Enabled: true, Endpoint: telemetryEndpoint, Version: version, Interval: 10 * time.Minute}
		go tc.Run(stop)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(stop)
}

func runShell() {
	p, _, _ := newProxy()
	addr, err := p.Start(0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sh := os.Getenv("SHELL")
	if sh == "" {
		sh = "/bin/sh"
	}
	c := exec.Command(sh)
	c.Env = append(os.Environ(), "HTTPS_PROXY="+addr, "HTTP_PROXY="+addr)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	_ = c.Run()
}
