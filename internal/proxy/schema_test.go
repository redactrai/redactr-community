package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/redactrai/redactr-community/internal/scanner"
)

// TestHandleBody_PreservesToolSchemas is the regression test for the bug where
// redacting strings inside tool/function definitions corrupted their JSON Schema
// and the provider rejected the request:
//   API Error 400 tools.0.custom.input_schema: JSON schema is invalid.
// A real request (tools + a secret in the user message) must come out with the
// tool schema byte-for-byte intact AND the user-message secret redacted.
func TestHandleBody_PreservesToolSchemas(t *testing.T) {
	body := []byte(`{
	  "model":"claude-3-5-sonnet",
	  "tools":[{
	    "name":"get_weather",
	    "description":"Look up weather. example token f3Kq9zR2pX7wL4mN8vC1bH6tY0sD5gJ2aE4uI9o",
	    "input_schema":{
	      "$schema":"https://json-schema.org/draft/2020-12/schema",
	      "type":"object",
	      "properties":{"city":{"type":"string","description":"e.g. AKIAIOSFODNN7EXAMPLE"}},
	      "required":["city"]
	    }
	  }],
	  "messages":[{"role":"user","content":"my key is AKIAIOSFODNN7EXAMPLE"}]
	}`)

	h := newBodyHandler(scanner.New().Redact)
	out, n, err := h.handleBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected the user-message secret to be redacted")
	}
	s := string(out)

	// 1) Tool schema must be untouched — the $schema URL and the in-schema strings
	//    (which the URL/entropy patterns WOULD otherwise redact) must survive.
	if !strings.Contains(s, "https://json-schema.org/draft/2020-12/schema") {
		t.Errorf("tool input_schema $schema URL was corrupted:\n%s", s)
	}
	if !strings.Contains(s, "f3Kq9zR2pX7wL4mN8vC1bH6tY0sD5gJ2aE4uI9o") {
		t.Errorf("a high-entropy string inside the tool definition was redacted (breaks the schema):\n%s", s)
	}

	// 2) Output is valid JSON and the user-message secret IS redacted.
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	msgs, ok := parsed["messages"].([]interface{})
	if !ok || len(msgs) == 0 {
		t.Fatalf("messages missing from output: %s", s)
	}
	uc, _ := msgs[0].(map[string]interface{})["content"].(string)
	if strings.Contains(uc, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("user-message secret was NOT redacted: %q", uc)
	}
}
