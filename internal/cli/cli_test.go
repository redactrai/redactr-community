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
