package systemproxy

import (
	"path/filepath"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "proxy-state.json")
	in := &state{Services: []serviceState{{Name: "Wi-Fi", HTTPSEnabled: false}}}
	if err := saveState(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := loadState(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Services) != 1 || out.Services[0].Name != "Wi-Fi" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}
