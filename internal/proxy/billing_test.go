package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/redactrai/redactr-community/internal/scanner"
)

// TestHandleBody_PreservesBillingBlock is the regression test for the real bug:
// re-serializing the body reordered JSON keys and broke Anthropic's recognition
// of Claude Code's first system block (x-anthropic-billing-header), producing
//
//	400 x-anthropic-billing-header is a reserved keyword and may not be used in
//	the system prompt.
//
// With surgical byte-replacement, the billing block stays byte-identical (keys in
// the original {type,text} order) while the user-message email is still redacted.
// It fails if handleBody ever goes back to re-marshalling the whole body.
func TestHandleBody_PreservesBillingBlock(t *testing.T) {
	const billing = `{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.183.ea1; cc_entrypoint=cli; cch=1238c;"}`
	body := []byte(`{"model":"claude-haiku-4-5-20251001","messages":[{"role":"user","content":[{"type":"text","text":"can you see my email rguha@something.com"}]}],"system":[` +
		billing + `,{"type":"text","text":"You are Claude Code."}],"tools":[]}`)

	h := newBodyHandler(scannerFind(scanner.New()))
	out, n, err := h.handleBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected the email to be redacted")
	}
	s := string(out)
	if !strings.Contains(s, billing) {
		t.Errorf("billing system block was altered (key order/bytes changed):\n%s", s)
	}
	if strings.Contains(s, "rguha@something.com") {
		t.Errorf("email was not redacted:\n%s", s)
	}
	var p map[string]interface{}
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}
