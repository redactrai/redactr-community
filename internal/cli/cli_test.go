package cli

import "strings"

import "testing"

func TestTelemetryBannerMentionsOptInAndAnonymous(t *testing.T) {
	b := strings.ToLower(TelemetryBanner())
	for _, want := range []string{"opt-in", "anonymous", "telemetry on"} {
		if !strings.Contains(b, want) {
			t.Errorf("banner missing %q", want)
		}
	}
}

func TestProxyEnv(t *testing.T) {
	env := ProxyEnv("http://127.0.0.1:8080", "/home/u/.redactr-community/ca.pem")
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"HTTPS_PROXY=http://127.0.0.1:8080",
		"HTTP_PROXY=http://127.0.0.1:8080",
		"NODE_EXTRA_CA_CERTS=/home/u/.redactr-community/ca.pem",
		"SSL_CERT_FILE=/home/u/.redactr-community/ca.pem",
		"SSL_CERT_DIR=",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("ProxyEnv missing %q; got %v", want, env)
		}
	}
}
