package proxy

import (
	"encoding/json"
	"strings"
)

// ReplaceLastUserMessage rebuilds the JSON body, replacing the text of the
// message described by msg with redactedText. It returns the new JSON bytes.
func ReplaceLastUserMessage(body []byte, msg *ExtractedMessage, redactedText string) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(raw["messages"], &messages); err != nil {
		return nil, err
	}

	if msg.IsArray {
		// Re-distribute the redacted text back into the parts.
		redactedParts := make([]ContentPart, len(msg.ContentParts))
		texts := strings.Split(redactedText, "\n")
		textIdx := 0
		for i, p := range msg.ContentParts {
			redactedParts[i] = p
			switch p.Type {
			case "text":
				if textIdx < len(texts) {
					redactedParts[i].Text = texts[textIdx]
					textIdx++
				}
			case "tool_result":
				if textIdx < len(texts) {
					redactedParts[i].Content = texts[textIdx]
					textIdx++
				}
			}
		}
		partBytes, err := json.Marshal(redactedParts)
		if err != nil {
			return nil, err
		}
		msgObj := map[string]json.RawMessage{
			"role":    json.RawMessage(`"user"`),
			"content": partBytes,
		}
		msgBytes, err := json.Marshal(msgObj)
		if err != nil {
			return nil, err
		}
		messages[msg.Index] = msgBytes
	} else {
		contentBytes, err := json.Marshal(redactedText)
		if err != nil {
			return nil, err
		}
		msgObj := map[string]json.RawMessage{
			"role":    json.RawMessage(`"user"`),
			"content": contentBytes,
		}
		msgBytes, err := json.Marshal(msgObj)
		if err != nil {
			return nil, err
		}
		messages[msg.Index] = msgBytes
	}

	msgBytes, err := json.Marshal(messages)
	if err != nil {
		return nil, err
	}
	raw["messages"] = msgBytes

	return json.Marshal(raw)
}
