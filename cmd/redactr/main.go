package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redactrai/redactr-community/internal/catrust"
	"github.com/redactrai/redactr-community/internal/certgen"
	"github.com/redactrai/redactr-community/internal/cli"
	"github.com/redactrai/redactr-community/internal/config"
	"github.com/redactrai/redactr-community/internal/daemon"
	"github.com/redactrai/redactr-community/internal/filescan"
	"github.com/redactrai/redactr-community/internal/proxy"
	"github.com/redactrai/redactr-community/internal/scanner"
	"github.com/redactrai/redactr-community/internal/systemproxy"
	"github.com/redactrai/redactr-community/internal/telemetry"
)

var version = "dev" // set via -ldflags at release

const telemetryEndpoint = "https://t.redactrai.com/beat"
const proxyHostPort = "127.0.0.1:8080"

func caPaths() (string, string) {
	d := config.Dir()
	return filepath.Join(d, "ca.pem"), filepath.Join(d, "ca.key")
}

func main() {
	config.Migrate()
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
	case "run":
		runRun(os.Args[2:])
	case "shell":
		runShell()
	case "start":
		runStart()
	case "__daemon":
		runDaemon()
	case "enable":
		runEnable()
	case "disable":
		runDisable()
	case "status":
		runStatus()
	case "doctor":
		runDoctor()
	case "allow":
		runAllow(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	default:
		fmt.Println("usage: redactr [start | run <command> | shell | ca | allow <host> | enable | disable | status | doctor | telemetry on|off|status | scan [--redact --yes] <path>]")
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
	// find returns the secrets in a content string so the proxy can redact them
	// with surgical byte-level replacement (never re-serializing the body).
	find := func(text string) []proxy.Replacement {
		res, err := s.Scan(text)
		if err != nil {
			return nil
		}
		out := make([]proxy.Replacement, 0, len(res.Findings))
		for _, f := range res.Findings {
			if f.Value != "" {
				out = append(out, proxy.Replacement{Old: f.Value, New: "[REDACTED-" + f.Label + "]"})
			}
		}
		return out
	}
	p, err := proxy.New(ca, find, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		os.Exit(1)
	}
	return p, cert, key
}

// quietLogs suppresses verbose slog output — used by the daemon subprocess.
func quietLogs() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// proxyRunning reports whether something is already listening on the proxy port.
func proxyRunning(hostport string) bool {
	c, err := net.DialTimeout("tcp", hostport, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ensureProxy returns the proxy URL, starting an in-process proxy if one isn't
// already running. The returned stop channel (nil when reusing an existing proxy)
// must be closed by the caller when done.
func ensureProxy() (addr string, stop chan struct{}) {
	addr = "http://" + proxyHostPort
	if proxyRunning(proxyHostPort) {
		fmt.Fprintln(os.Stderr, "redactr: using the proxy already running on "+addr)
		return addr, nil
	}
	p, _, _ := newProxy()
	if _, err := p.Start(8080); err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "redactr: started proxy on "+addr)
	stop = make(chan struct{})
	if config.Load().TelemetryEnabled {
		go (&telemetry.Client{Enabled: true, Endpoint: telemetryEndpoint, Version: version, Interval: 10 * time.Minute}).Run(stop)
	}
	return addr, stop
}

func runStart() {
	cli.MaybeShowFirstRun()
	p, cert, _ := newProxy()
	addr, err := p.Start(8080)
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		os.Exit(1)
	}
	fmt.Printf("redactr proxy listening on %s\n", addr)
	fmt.Println(cli.TrustInstructions(cert))
	fmt.Printf("Then: export HTTPS_PROXY=%s   (or use `redactr run <tool>`)\n", addr)

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

// runRun ensures the proxy is up, then launches the given command in a shell that
// already carries the proxy environment (e.g. `redactr run claude`).
// For GUI tools, it prints an informational note instead of injecting proxy env
// (GUI apps cannot inherit terminal env vars; the system proxy daemon protects them).
func runRun(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: redactr run <command> [args...]    e.g. redactr run claude")
		return
	}
	cli.MaybeShowFirstRun()
	if cli.IsGUI(args[0]) {
		fmt.Fprintf(os.Stderr, "note: %s is a GUI tool — env vars don't reach GUI apps.\n", args[0])
		fmt.Fprintln(os.Stderr, "      GUI tools are protected by the system proxy when the daemon is enabled.")
		fmt.Fprintln(os.Stderr, "      Ensure it's on with: redactr enable")
		sh := os.Getenv("SHELL")
		if sh == "" {
			sh = "/bin/sh"
		}
		c := exec.Command(sh, "-c", strings.Join(args, " "))
		c.Env = os.Environ()
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		_ = c.Run()
		return
	}
	cert, _ := caPaths()
	addr, stop := ensureProxy()
	sh := os.Getenv("SHELL")
	if sh == "" {
		sh = "/bin/sh"
	}
	c := exec.Command(sh, "-c", strings.Join(args, " "))
	c.Env = append(os.Environ(), cli.ProxyEnv(addr, cert)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	_ = c.Run()
	if stop != nil {
		close(stop)
	}
}

// runShell ensures the proxy is up, then opens an interactive shell with the
// proxy environment attached.
func runShell() {
	cli.MaybeShowFirstRun()
	cert, _ := caPaths()
	addr, stop := ensureProxy()
	sh := os.Getenv("SHELL")
	if sh == "" {
		sh = "/bin/sh"
	}
	c := exec.Command(sh)
	c.Env = append(os.Environ(), cli.ProxyEnv(addr, cert)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	_ = c.Run()
	if stop != nil {
		close(stop)
	}
}

// runDaemon is the hidden handler invoked by daemon.Start — runs the proxy in the
// background and reverts the system proxy on termination.
func runDaemon() {
	port := 8080
	for i, a := range os.Args {
		if a == "--port" && i+1 < len(os.Args) {
			if p, err := strconv.Atoi(os.Args[i+1]); err == nil {
				port = p
			}
		}
	}
	quietLogs()
	p, _, _ := newProxy()
	if _, err := p.Start(port); err != nil {
		fmt.Fprintln(os.Stderr, "daemon proxy error:", err)
		os.Exit(1)
	}
	// On termination, revert the system proxy so the machine keeps working.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = systemproxy.Revert(config.ProxyStatePath())
	os.Exit(0)
}

// runEnable trusts the CA, starts the daemon, and sets the system proxy.
func runEnable() {
	cert, _ := caPaths()
	// ensure CA exists (newProxy creates it if missing)
	if _, err := os.Stat(cert); err != nil {
		_, _, _ = newProxy()
	}
	if ok, _ := catrust.IsTrusted(cert); !ok {
		fmt.Println("Trusting the local CA (you may be prompted for your password)…")
		if err := catrust.Install(cert); err != nil {
			fmt.Fprintln(os.Stderr, "CA trust failed:", err)
			os.Exit(1)
		}
	}
	if err := daemon.Start(8080); err != nil {
		fmt.Fprintln(os.Stderr, "daemon start failed:", err)
		os.Exit(1)
	}
	if err := systemproxy.Set("127.0.0.1", 8080, config.ProxyStatePath()); err != nil {
		fmt.Fprintln(os.Stderr, "system proxy set failed:", err)
		os.Exit(1)
	}
	fmt.Println("✓ Redactr is on. Every AI tool (terminal and GUI) is now protected.")
	fmt.Println("  Turn it off any time with: redactr disable")
}

// runDisable reverts the system proxy, stops the daemon, and optionally untrusts the CA.
func runDisable() {
	untrust := false
	for _, a := range os.Args[2:] {
		if a == "--untrust" {
			untrust = true
		}
	}
	_ = systemproxy.Revert(config.ProxyStatePath())
	_ = daemon.Stop()
	if untrust {
		cert, _ := caPaths()
		_ = catrust.Remove(cert)
	}
	fmt.Println("✓ Redactr is off. System proxy reverted.")
}

// runStatus prints daemon, CA trust, and system proxy state.
func runStatus() {
	cert, _ := caPaths()

	running, info := daemon.IsRunning()
	if running {
		fmt.Printf("daemon:       running (pid %d, port %d)\n", info.PID, info.Port)
	} else {
		fmt.Println("daemon:       not running")
	}

	trusted, err := catrust.IsTrusted(cert)
	if err != nil {
		fmt.Printf("CA trusted:   unknown (%v)\n", err)
	} else if trusted {
		fmt.Println("CA trusted:   yes")
	} else {
		fmt.Println("CA trusted:   no")
	}

	set, err := systemproxy.IsSet("127.0.0.1", 8080)
	if err != nil {
		fmt.Printf("system proxy: unknown (%v)\n", err)
	} else if set {
		fmt.Println("system proxy: set → 127.0.0.1:8080")
	} else {
		fmt.Println("system proxy: not set")
	}

	// Stale-state guard: proxy points at a dead port.
	if set && !running {
		fmt.Println()
		fmt.Println("WARNING: The system proxy is set but the Redactr daemon is NOT running.")
		fmt.Println("         All proxied traffic will fail until you restore internet access.")
		fmt.Println("         Run:  redactr disable")
	}
}

// runDoctor runs status checks plus a live interception probe through the proxy.
func runDoctor() {
	runStatus()

	running, _ := daemon.IsRunning()
	if !running {
		return
	}

	cert, _ := caPaths()

	// Build an x509 pool that trusts our local CA.
	pool := x509.NewCertPool()
	if b, err := os.ReadFile(cert); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				pool.AddCert(c)
			}
		}
	}

	proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}

	fmt.Println()
	fmt.Println("live interception probe:")
	for _, host := range []string{"api.anthropic.com", "api.openai.com"} {
		target := "https://" + host + "/"
		req, _ := http.NewRequest(http.MethodHead, target, nil)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("  %-30s could not verify (offline?): %v\n", host, err)
			continue
		}
		_ = resp.Body.Close()
		hdr := resp.Header.Get("X-Redactr-Status")
		if hdr != "" {
			fmt.Printf("  %-30s intercepted ✓ (X-Redactr-Status: %s)\n", host, hdr)
		} else {
			fmt.Printf("  %-30s reached but header absent\n", host)
		}
	}
}

// runScan walks the given paths (default: ".") looking for secrets. With --redact
// --yes it rewrites matching files in place. Without --redact it reports findings
// and exits non-zero (CI/pre-commit friendly).
func runScan(args []string) {
	redactMode, yes := false, false
	var paths []string
	for _, a := range args {
		switch a {
		case "--redact":
			redactMode = true
		case "--yes", "-y":
			yes = true
		default:
			paths = append(paths, a)
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	sc := scanner.New()
	if redactMode {
		if !yes {
			fmt.Fprintln(os.Stderr, "refusing to modify files without --yes (this rewrites files in place). Re-run: redactr scan --redact --yes <path>")
			os.Exit(2)
		}
		total := 0
		for _, p := range paths {
			_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				n, _ := filescan.RedactFile(path, sc)
				if n > 0 {
					total += n
					fmt.Printf("redacted %d in %s\n", n, path)
				}
				return nil
			})
		}
		fmt.Printf("done: %d redactions written\n", total)
		return
	}
	// report-only (default)
	var all []filescan.Finding
	for _, p := range paths {
		found, err := filescan.Scan(p, sc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan error:", err)
			os.Exit(1)
		}
		all = append(all, found...)
	}
	for _, f := range all {
		fmt.Printf("%s:%d  %s\n", f.Path, f.Line, f.Label)
	}
	if len(all) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d secret(s) found.\n", len(all))
		os.Exit(1)
	}
	fmt.Println("no secrets found.")
}

// runAllow appends each host argument to the user allowlist file so the daemon
// MITM-decrypts those hosts on next restart.
func runAllow(hosts []string) {
	if len(hosts) == 0 {
		fmt.Println("usage: redactr allow <host> [host ...]")
		fmt.Println("       e.g. redactr allow api.example.com")
		return
	}
	path := config.AllowPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fmt.Fprintln(os.Stderr, "allow: cannot create config dir:", err)
		os.Exit(1)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "allow: cannot open allowlist:", err)
		os.Exit(1)
	}
	defer f.Close()
	for _, h := range hosts {
		if _, err := fmt.Fprintln(f, h); err != nil {
			fmt.Fprintln(os.Stderr, "allow: write error:", err)
			os.Exit(1)
		}
		fmt.Printf("added %s to the allowlist — restart the daemon (redactr disable && enable) to apply.\n", h)
	}
}
