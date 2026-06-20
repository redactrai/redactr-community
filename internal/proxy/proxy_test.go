package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/redactrai/redactr-community/internal/scanner"
)

// fakeFind is a simple find func for testing: flags the literal "SECRET".
func fakeFind(text string) []Replacement {
	if strings.Contains(text, "SECRET") {
		return []Replacement{{Old: "SECRET", New: "[REDACTED-SECRET]"}}
	}
	return nil
}

// scannerFind adapts a real scanner into the proxy's find func.
func scannerFind(sc *scanner.RegexScanner) func(string) []Replacement {
	return func(text string) []Replacement {
		res, err := sc.Scan(text)
		if err != nil {
			return nil
		}
		var out []Replacement
		for _, f := range res.Findings {
			if f.Value != "" {
				out = append(out, Replacement{Old: f.Value, New: "[REDACTED-" + f.Label + "]"})
			}
		}
		return out
	}
}

// buildBody constructs a minimal OpenAI-style JSON request body with a single
// user message containing the given content string.
func buildBody(t *testing.T, content string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]interface{}{
			{"role": "user", "content": content},
		},
	})
	if err != nil {
		t.Fatalf("buildBody: %v", err)
	}
	return body
}

// buildBodyArray constructs a request body where the user message content is
// an array of parts (e.g. Claude-style multi-part content).
func buildBodyArray(t *testing.T, textPart string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"model": "claude-3-5-sonnet",
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{"type": "text", "text": textPart},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("buildBodyArray: %v", err)
	}
	return body
}

// ---- Tests ----

// TestHandleBody_CleanMessage verifies that a body with no secrets passes through unchanged.
func TestHandleBody_CleanMessage(t *testing.T) {
	h := newBodyHandler(fakeFind)
	input := buildBody(t, "Hello, what is the weather?")

	out, n, err := h.handleBody(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 redactions, got %d", n)
	}
	// Body bytes should be identical (no rewrite needed).
	if string(out) != string(input) {
		t.Errorf("expected unchanged body, got: %s", out)
	}
}

// TestHandleBody_SecretIsRedacted verifies that a body containing "SECRET" is
// rewritten with [REDACTED-SECRET] in the user message content.
func TestHandleBody_SecretIsRedacted(t *testing.T) {
	h := newBodyHandler(fakeFind)
	// Use a longer phrase so we can check the original phrase is gone even
	// though [REDACTED-SECRET] itself contains the substring "SECRET".
	input := buildBody(t, "My password is SECRET and I need help.")

	out, n, err := h.handleBody(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Error("expected at least 1 redaction, got 0")
	}

	// The output body must contain the redaction placeholder.
	if !strings.Contains(string(out), "[REDACTED-SECRET]") {
		t.Errorf("output body missing '[REDACTED-SECRET]': %s", out)
	}
	// The original bare word "SECRET" must appear only inside the placeholder,
	// not as a standalone value. We verify this by checking the placeholder
	// replaced the original text (original context phrase is absent).
	if strings.Contains(string(out), "is SECRET and") {
		t.Errorf("output body still contains un-redacted phrase 'is SECRET and': %s", out)
	}
	// The output must still be valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Errorf("output body is not valid JSON: %v\nbody: %s", err, out)
	}
}

// TestHandleBody_SecretInArrayContent verifies redaction works when the user
// message content is a JSON array of typed parts (multi-part / Claude format).
func TestHandleBody_SecretInArrayContent(t *testing.T) {
	h := newBodyHandler(fakeFind)
	input := buildBodyArray(t, "Here is my token: SECRET")

	out, n, err := h.handleBody(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n == 0 {
		t.Error("expected at least 1 redaction, got 0")
	}
	if !strings.Contains(string(out), "[REDACTED-SECRET]") {
		t.Errorf("output body missing '[REDACTED-SECRET]': %s", out)
	}
	// The original unredacted context phrase must be gone.
	if strings.Contains(string(out), "token: SECRET") {
		t.Errorf("output body still contains unredacted phrase 'token: SECRET': %s", out)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Errorf("output body is not valid JSON: %v", err)
	}
}

// TestHandleBody_NonJSONPassthrough verifies that a non-JSON body is returned
// unchanged and no error is reported (fail-open).
func TestHandleBody_NonJSONPassthrough(t *testing.T) {
	h := newBodyHandler(fakeFind)
	input := []byte("this is not JSON")

	out, n, err := h.handleBody(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 redactions for non-JSON body, got %d", n)
	}
	if string(out) != string(input) {
		t.Errorf("expected passthrough for non-JSON, got: %s", out)
	}
}

// TestHandleBody_ContentLengthSemantics verifies that the rewritten body's
// length matches what Content-Length should be set to.
func TestHandleBody_ContentLengthSemantics(t *testing.T) {
	h := newBodyHandler(fakeFind)
	input := buildBody(t, "Password: SECRET")

	out, _, err := h.handleBody(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The length of out is exactly what Content-Length should be.
	// Verify the placeholder is longer than the original secret.
	if len(out) <= len(input) {
		t.Errorf("rewritten body (%d bytes) should be longer than input (%d bytes) after adding placeholder", len(out), len(input))
	}
}

// TestHandleBody_MultipleSecretsRedacted verifies all occurrences in a message are redacted.
func TestHandleBody_MultipleSecretsRedacted(t *testing.T) {
	h := newBodyHandler(fakeFind)
	input := buildBody(t, "First SECRET and second SECRET here.")

	out, n, err := h.handleBody(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// fakeRedact counts each "SECRET" as 1 redaction (strings.Count).
	if n != 2 {
		t.Errorf("expected 2 redactions, got %d", n)
	}
	// Verify both placeholders are present.
	if strings.Count(string(out), "[REDACTED-SECRET]") != 2 {
		t.Errorf("expected 2 placeholders in output, got: %s", out)
	}
	// The original surrounding context must be gone.
	if strings.Contains(string(out), "First SECRET and") {
		t.Errorf("output body still contains unredacted 'First SECRET and': %s", out)
	}
}

// TestHandleBody_ArrayPartsWithNewlineAndEmptyToolResult is a regression test
// for two bugs that occurred together:
//  1. Newline join/split: joining array parts with "\n" then splitting on "\n"
//     to redistribute corrupted output when a part's text contained a literal newline.
//  2. tool_result asymmetry: an empty tool_result before a text part shifted the
//     rewrite index and left the secret in the wrong (or dropped) part.
func TestHandleBody_ArrayPartsWithNewlineAndEmptyToolResult(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","content":""},{"type":"text","text":"line1\nkey AKIA1234567890ABCD12 line2"}]}]}`)
	h := newBodyHandler(scannerFind(scanner.New()))
	out, n, err := h.handleBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected a redaction, got %d", n)
	}
	s := string(out)
	if strings.Contains(s, "AKIA1234567890ABCD12") {
		t.Errorf("secret survived: %s", s)
	}
	if !strings.Contains(s, "line1") || !strings.Contains(s, "line2") {
		t.Errorf("content truncated (newline bug): %s", s)
	}
}

// TestHandleBody_RedactsHistoryAndSystem is the regression test for the leak
// where only the LAST user message was redacted: conversation history, assistant
// messages, and the top-level system field passed through unredacted, so a secret
// typed in an earlier turn leaked once it became history.
func TestHandleBody_RedactsHistoryAndSystem(t *testing.T) {
	body := []byte(`{
	  "model":"claude-3-5-sonnet",
	  "max_tokens":1024,
	  "system":"account context SECRET-sys",
	  "messages":[
	    {"role":"user","content":"turn1 SECRET-a"},
	    {"role":"assistant","content":"sure, SECRET-b"},
	    {"role":"user","content":[{"type":"text","text":"turn2 SECRET-c"}]}
	  ]
	}`)
	h := newBodyHandler(fakeFind)
	out, n, err := h.handleBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatalf("expected >=4 redactions (system + 3 messages), got %d", n)
	}
	s := string(out)
	for _, leaked := range []string{"SECRET-sys", "SECRET-a", "SECRET-b", "SECRET-c"} {
		if strings.Contains(s, leaked) {
			t.Errorf("leaked %q in output: %s", leaked, s)
		}
	}
	// numbers must survive the re-marshal intact
	if !strings.Contains(s, "1024") {
		t.Errorf("max_tokens corrupted in re-marshal: %s", s)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Errorf("output not valid JSON: %v", err)
	}
}
