package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDisabledSendsNothing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	c := &Client{Enabled: false, Endpoint: srv.URL, Version: "test", Interval: 10 * time.Millisecond}
	c.beat()
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("disabled client must not send")
	}
}

func TestEnabledSendsAnonymousPayload(t *testing.T) {
	type beat struct {
		Session string `json:"session"`
		Version string `json:"version"`
		OS      string `json:"os"`
		IP      string `json:"ip"`
		Content string `json:"content"`
	}
	got := make(chan beat, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b beat
		_ = json.NewDecoder(r.Body).Decode(&b)
		got <- b
	}))
	defer srv.Close()
	c := &Client{Enabled: true, Endpoint: srv.URL, Version: "1.2.3", Interval: time.Minute}
	c.beat()
	select {
	case b := <-got:
		if b.Session == "" || b.Version != "1.2.3" || b.OS == "" {
			t.Fatalf("bad payload: %+v", b)
		}
		if b.IP != "" || b.Content != "" {
			t.Fatalf("payload leaked data: %+v", b)
		}
	case <-time.After(time.Second):
		t.Fatal("no beat received")
	}
}
