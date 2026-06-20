// Package proxy implements an HTTPS MITM proxy that redacts sensitive content
// in request bodies before forwarding them to upstream AI providers.
package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/redactrai/redactr-community/internal/certgen"
	"github.com/redactrai/redactr-community/internal/config"
)

// Proxy is an HTTPS MITM proxy that intercepts requests, redacts the last user
// message, and forwards the sanitised request to the upstream host.
type Proxy struct {
	goproxy  *goproxy.ProxyHttpServer
	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
	running  bool
	handler  *bodyHandler
}

// bodyHandler wraps the redact function and exposes a pure handleBody method
// that can be tested independently of the HTTP/TLS stack.
type bodyHandler struct {
	redact func(string) (string, int, error)
}

func newBodyHandler(redact func(string) (string, int, error)) *bodyHandler {
	return &bodyHandler{redact: redact}
}

// contentKeys are the top-level request fields that carry user/content text and
// are therefore redacted. Everything else in the request — tools, tool_choice,
// context_management, cache_control, model, metadata, ids, "type" discriminators,
// and any other structural/control field — is left byte-for-byte untouched.
//
// This is an ALLOWLIST on purpose. We previously redacted every string in the
// body, which corrupted app-defined structure (e.g. a tool's input_schema, or
// context_management edit "type" values like "clear_thinking_20251015") and made
// providers reject the request (HTTP 400). User secrets live in message content
// and system prompts — exactly what we redact here — so scoping to content keeps
// the protection while never breaking a request.
var contentKeys = []string{"system", "instructions", "prompt", "input"}

// handleBody redacts user-facing content in the JSON request body — every
// message's content (full history, all roles), the system/instructions prompt,
// tool-result content, and legacy prompt/input fields — without touching any
// structural field. Non-JSON / non-object bodies pass through unchanged.
func (h *bodyHandler) handleBody(body []byte) ([]byte, int, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep numbers exact across the re-marshal
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return body, 0, nil // not JSON — pass through
	}
	root, ok := v.(map[string]interface{})
	if !ok {
		return body, 0, nil // not a JSON object request — pass through
	}

	count := 0
	redactStr := func(s string) string {
		red, c, err := h.redact(s)
		if err != nil {
			slog.Warn("redact error, forwarding string unredacted", "error", err)
			return s
		}
		count += c
		return red
	}

	// redactContent redacts a content value that may be a plain string or an
	// array of typed parts (Anthropic/OpenAI message content). It only touches
	// text — never structural part fields like "type"/"name"/"id" — and recurses
	// into nested tool_result content.
	var redactContent func(c interface{}) interface{}
	redactContent = func(c interface{}) interface{} {
		switch cv := c.(type) {
		case string:
			return redactStr(cv)
		case []interface{}:
			for i, part := range cv {
				switch pv := part.(type) {
				case string:
					cv[i] = redactStr(pv)
				case map[string]interface{}:
					if t, ok := pv["text"].(string); ok {
						pv["text"] = redactStr(t)
					}
					if o, ok := pv["output"].(string); ok { // OpenAI responses tool output
						pv["output"] = redactStr(o)
					}
					if inner, ok := pv["content"]; ok { // tool_result / nested content
						pv["content"] = redactContent(inner)
					}
					cv[i] = pv
				}
			}
			return cv
		}
		return c
	}

	for _, key := range contentKeys {
		if val, ok := root[key]; ok {
			root[key] = redactContent(val)
		}
	}
	if msgs, ok := root["messages"].([]interface{}); ok {
		for _, m := range msgs {
			if mm, ok := m.(map[string]interface{}); ok {
				if c, ok := mm["content"]; ok {
					mm["content"] = redactContent(c)
				}
			}
		}
	}

	if count == 0 {
		return body, 0, nil // nothing matched — return the original bytes
	}
	out, err := json.Marshal(root)
	if err != nil {
		slog.Warn("body re-marshal failed, forwarding unredacted", "error", err)
		return body, 0, nil
	}
	return out, count, nil
}

// New creates a Proxy that uses ca for MITM TLS and the supplied redact
// function to sanitise request bodies.
//
// onRedact, if non-nil, is called after each request with the upstream host and
// the number of redactions applied (may be 0 for clean requests).
func New(ca *certgen.CA, redact func(string) (string, int, error), onRedact func(host string, n int)) (*Proxy, error) {
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false
	// Silence goproxy's own logger. Otherwise transport warnings (e.g. a client
	// closing mid-response -> "broken pipe") print to stderr and corrupt the TUI
	// of a tool launched via run/shell that shares this terminal.
	gp.Logger = log.New(io.Discard, "", 0)

	// Build a tls.Certificate from our CA so goproxy can sign leaf certs.
	tlsCert, err := buildTLSCert(ca)
	if err != nil {
		return nil, fmt.Errorf("build CA TLS cert: %w", err)
	}

	// Wire our CA into goproxy's global MITM signing state.
	// NOTE: GoproxyCa is a process-global in goproxy v1.8.3; there is no
	// per-instance CA. This is a known limitation of the library.
	goproxy.GoproxyCa = tlsCert

	bh := newBodyHandler(redact)

	p := &Proxy{
		goproxy: gp,
		handler: bh,
	}

	// Load the allowlist of AI-provider hosts to MITM-decrypt; tunnel everything else.
	allow := LoadAllowlist(config.AllowPath())

	// Intercept CONNECT tunnels with MITM only for allow-listed hosts; plain-tunnel the rest.
	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if allow.Match(host) {
			return goproxy.MitmConnect, host
		}
		return goproxy.OkConnect, host // plain tunnel — no decryption
	})

	// For every intercepted request: read body → redact → rewrite if needed.
	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if req.Body == nil {
			ctx.UserData = statusClean
			return req, nil
		}

		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			ctx.UserData = statusPassthrough
			return req, nil
		}

		newBody, n, _ := bh.handleBody(body)

		var status string
		if n > 0 {
			status = statusFull
		} else {
			status = statusClean
		}

		req.Body = io.NopCloser(bytes.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		ctx.UserData = status

		if onRedact != nil {
			onRedact(req.Host, n)
		}

		return req, nil
	})

	// Stamp X-Redactr-Status on every response.
	gp.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil {
			if status, ok := ctx.UserData.(string); ok {
				resp.Header.Set("X-Redactr-Status", status)
			}
		}
		return resp
	})

	return p, nil
}

// Start begins listening on 127.0.0.1:port in a background goroutine and
// returns the actual address as "http://127.0.0.1:<port>". When port is 0 the
// OS chooses an ephemeral port; the returned addr reflects the actual port.
func (p *Proxy) Start(port int) (addr string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", err
	}

	p.server = &http.Server{Handler: p.goproxy}
	p.running = true
	go p.server.Serve(p.listener) //nolint:errcheck

	return "http://" + p.listener.Addr().String(), nil
}

// Stop shuts down the proxy.
func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return nil
	}
	p.running = false
	return p.server.Close()
}

// Addr returns the listening address (empty if not started).
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// Status constants placed on ctx.UserData and echoed in X-Redactr-Status.
const (
	statusClean       = "clean"
	statusFull        = "full"
	statusPassthrough = "passthrough"
)

// buildTLSCert converts our certgen.CA into a tls.Certificate that goproxy
// can use to sign leaf certificates on-the-fly.
func buildTLSCert(ca *certgen.CA) (tls.Certificate, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	keyDER, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	// goproxy reads Leaf for signing, so parse it explicitly.
	if tlsCert.Leaf == nil {
		tlsCert.Leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, err
		}
	}
	return tlsCert, nil
}
