package proxy

import (
	"encoding/json"
	"fmt"
)

// ExtractedMessage holds the extracted user message text and the metadata
// needed to reconstruct (rewrite) the body after redaction.
type ExtractedMessage struct {
	// Text is the concatenated plaintext of the user message.
	// For array content this is only used to signal non-emptiness; actual
	// per-part redaction uses PartTexts / ContentParts directly.
	Text string
	// Index is the position of this message in the messages array.
	Index int
	// ContentParts holds the parsed parts when content was a JSON array.
	ContentParts []ContentPart
	// PartTexts holds the original extractable text for each ContentPart, in
	// the same order as ContentParts. An empty string means the part has no
	// text to redact (e.g. an empty tool_result).
	PartTexts []string
	// IsArray is true when the original content was an array of parts.
	IsArray bool
}

// ContentPart represents one element in a multi-part content array.
type ContentPart struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Content   string `json:"content,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`
}

type apiRequest struct {
	Messages []apiMessage `json:"messages"`
}

type apiMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// ExtractLastUserMessage finds the last user-role message in an OpenAI/Anthropic
// style JSON request body and returns an ExtractedMessage. The content may be
// either a plain string or a JSON array of typed parts.
func ExtractLastUserMessage(body []byte) (*ExtractedMessage, error) {
	var req apiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse request body: %w", err)
	}

	for i := len(req.Messages) - 1; i >= 0; i-- {
		msg := req.Messages[i]
		if msg.Role != "user" {
			continue
		}

		// Try string content first.
		var strContent string
		if err := json.Unmarshal(msg.Content, &strContent); err == nil {
			return &ExtractedMessage{Text: strContent, Index: i}, nil
		}

		// Try array-of-parts content.
		// Each text-bearing part is stored independently in PartTexts so that
		// rewriting never needs to split on a separator character (which would
		// corrupt part text that itself contains that character).
		var parts []ContentPart
		if err := json.Unmarshal(msg.Content, &parts); err == nil {
			partTexts := make([]string, len(parts))
			combined := ""
			for j, p := range parts {
				switch p.Type {
				case "text":
					partTexts[j] = p.Text
					combined += p.Text
				case "tool_result":
					// Only populate PartTexts for non-empty tool_result content;
					// empty entries are left as "" so rewrite skips them too.
					partTexts[j] = p.Content
					combined += p.Content
				}
			}
			return &ExtractedMessage{
				Text:         combined,
				Index:        i,
				ContentParts: parts,
				PartTexts:    partTexts,
				IsArray:      true,
			}, nil
		}

		return nil, fmt.Errorf("unsupported content format at message %d", i)
	}

	return nil, fmt.Errorf("no user message found")
}
