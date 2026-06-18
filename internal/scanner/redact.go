package scanner

import (
	"fmt"
	"sort"
)

// Redact replaces every detected finding with [REDACTED-<LABEL>].
// Returns redacted text and the number of redactions. Applies right-to-left
// so offsets stay valid; skips overlapping matches.
func (s *RegexScanner) Redact(text string) (string, int, error) {
	result, err := s.Scan(text)
	if err != nil {
		return text, 0, err
	}

	if len(result.Findings) == 0 {
		return text, 0, nil
	}

	// Sort findings by start position descending (right-to-left application).
	findings := result.Findings
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Start > findings[j].Start
	})

	// Apply replacements right-to-left, skipping overlaps.
	out := []byte(text)
	count := 0
	lastStart := len(text) // tracks the leftmost boundary of previously replaced region

	for _, f := range findings {
		// Skip if this finding overlaps with an already-replaced region.
		if f.End > lastStart {
			continue
		}
		replacement := fmt.Sprintf("[REDACTED-%s]", f.Label)
		out = append(out[:f.Start], append([]byte(replacement), out[f.End:]...)...)
		lastStart = f.Start
		count++
	}

	return string(out), count, nil
}
