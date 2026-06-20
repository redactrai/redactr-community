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

	h := newBodyHandler(scannerFind(scanner.New()))
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

// TestHandleBody_PreservesControlFields covers the broader class of bug: every
// structural/control field a real client sends (model, context_management edit
// "type" enums, tool schemas, cache_control) must pass through untouched, while
// only user content is redacted. Mirrors the real 400s we hit:
//   tools.0.custom.input_schema: JSON schema is invalid
//   context_management.edits.0: Input tag '[REDACTED-HIGH-ENTROPY]' ...
func TestHandleBody_PreservesControlFields(t *testing.T) {
	body := []byte(`{
	  "model":"claude-sonnet-4-5-20250929",
	  "context_management":{"edits":[{"type":"clear_thinking_20251015"}]},
	  "tools":[{"name":"x","input_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}}],
	  "system":[{"type":"text","text":"be helpful","cache_control":{"type":"ephemeral"}}],
	  "messages":[{"role":"user","content":"email me at rguha@something.com"}]
	}`)
	h := newBodyHandler(scannerFind(scanner.New()))
	out, n, err := h.handleBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected the email in user content to be redacted")
	}
	s := string(out)
	for _, must := range []string{
		"clear_thinking_20251015",                       // context_management edit type
		"claude-sonnet-4-5-20250929",                    // model
		"https://json-schema.org/draft/2020-12/schema",  // tool input_schema $schema
		`"type":"ephemeral"`,                            // cache_control
	} {
		if !strings.Contains(s, must) {
			t.Errorf("structural value corrupted — missing %q:\n%s", must, s)
		}
	}
	if strings.Contains(s, "rguha@something.com") {
		t.Errorf("user email was NOT redacted:\n%s", s)
	}
}

// TestHandleBody_RedactsToolResultContent: a tool (grep/search/read) returned
// content containing a secret; it comes back as a tool_result and MUST be
// redacted before reaching the provider — while the tool_use call args and the
// structural fields (type, tool_use_id) stay intact.
func TestHandleBody_RedactsToolResultContent(t *testing.T) {
	body := []byte(`{
	  "model":"claude-3-5-sonnet",
	  "messages":[
	    {"role":"assistant","content":[{"type":"tool_use","id":"tu_1","name":"grep","input":{"q":"key"}}]},
	    {"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"match: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdefK7MDENGbPxRfiCYEXAMPLE"}]}
	  ]
	}`)
	h := newBodyHandler(scannerFind(scanner.New()))
	out, n, err := h.handleBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected the secret in tool_result content to be redacted")
	}
	s := string(out)
	if strings.Contains(s, "wJalrXUtnFEMIabcdefK7MDENGbPxRfiCYEXAMPLE") {
		t.Errorf("secret in tool_result content was NOT redacted:\n%s", s)
	}
	if !strings.Contains(s, "tu_1") || !strings.Contains(s, `"type":"tool_use"`) {
		t.Errorf("tool_use structural fields corrupted:\n%s", s)
	}
}
