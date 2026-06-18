// Package proxy implements an HTTPS MITM proxy that redacts sensitive content
// in request bodies before forwarding them to upstream AI providers.
package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/redactrai/redactr-community/internal/certgen"
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

// handleBody extracts the last user message from a JSON request body, runs the
// redact function, and — if the text changed — rewrites the body. It returns
// the (possibly new) body bytes and the number of redactions applied.
//
// On any parse/rewrite error the original body is returned unchanged (fail-open).
func (h *bodyHandler) handleBody(body []byte) ([]byte, int, error) {
	msg, err := ExtractLastUserMessage(body)
	if err != nil {
		// Not a recognised JSON structure — pass through silently.
		return body, 0, nil
	}

	redactedText, n, err := h.redact(msg.Text)
	if err != nil {
		slog.Warn("redact error, forwarding unredacted", "error", err)
		return body, 0, nil
	}

	if n == 0 {
		// Nothing to redact; return the original bytes unchanged.
		return body, 0, nil
	}

	newBody, err := ReplaceLastUserMessage(body, msg, redactedText)
	if err != nil {
		slog.Warn("body rewrite failed", "error", err)
		return body, 0, nil
	}
	return newBody, n, nil
}

// New creates a Proxy that uses ca for MITM TLS and the supplied redact
// function to sanitise request bodies.
//
// onRedact, if non-nil, is called after each request with the upstream host and
// the number of redactions applied (may be 0 for clean requests).
func New(ca *certgen.CA, redact func(string) (string, int, error), onRedact func(host string, n int)) (*Proxy, error) {
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false

	// Build a tls.Certificate from our CA so goproxy can sign leaf certs.
	tlsCert, err := buildTLSCert(ca)
	if err != nil {
		return nil, fmt.Errorf("build CA TLS cert: %w", err)
	}

	// Wire our CA into goproxy's global MITM state.
	goproxy.GoproxyCa = tlsCert
	tlsConfigFn := goproxy.TLSConfigFromCA(&goproxy.GoproxyCa)

	// Override the three connect actions to all use our CA.
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfigFn}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfigFn}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject}

	bh := newBodyHandler(redact)

	p := &Proxy{
		goproxy: gp,
		handler: bh,
	}

	// Intercept ALL CONNECT tunnels with MITM.
	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return goproxy.MitmConnect, host
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
