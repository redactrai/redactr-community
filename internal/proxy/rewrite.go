package proxy

import (
	"encoding/json"
)

// ReplaceLastUserMessage rebuilds the JSON body, replacing the text of the
// message described by msg with the per-part redacted texts in redactedParts
// (for array content) or with redactedText (for string content).
//
// For array content, redactedParts must be the same length as msg.PartTexts;
// each entry is the redacted version of the corresponding msg.PartTexts entry.
func ReplaceLastUserMessage(body []byte, msg *ExtractedMessage, redactedText string, redactedParts []string) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(raw["messages"], &messages); err != nil {
		return nil, err
	}

	if msg.IsArray {
		// Rebuild the parts array, substituting each part's redacted text.
		// redactedParts is parallel to msg.ContentParts / msg.PartTexts.
		rebuilt := make([]ContentPart, len(msg.ContentParts))
		for i, p := range msg.ContentParts {
			rebuilt[i] = p
			switch p.Type {
			case "text":
				rebuilt[i].Text = redactedParts[i]
			case "tool_result":
				rebuilt[i].Content = redactedParts[i]
			}
		}
		partBytes, err := json.Marshal(rebuilt)
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
