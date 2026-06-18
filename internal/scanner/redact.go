package scanner

import (
	"fmt"
	"sort"
)

// Redact replaces detected findings with [REDACTED-<LABEL>]. When matches overlap,
// it prefers the widest enclosing match. Returns redacted text and the count applied.
func (s *RegexScanner) Redact(text string) (string, int, error) {
	res, err := s.Scan(text)
	if err != nil {
		return text, 0, err
	}
	f := res.Findings
	if len(f) == 0 {
		return text, 0, nil
	}
	// Order left-to-right; on equal Start, the wider span (larger End) comes first.
	sort.Slice(f, func(i, j int) bool {
		if f[i].Start != f[j].Start {
			return f[i].Start < f[j].Start
		}
		return f[i].End > f[j].End
	})
	// Greedily select non-overlapping spans; an inner/overlapping match is dropped
	// in favor of the earlier, wider one.
	selected := make([]Finding, 0, len(f))
	lastEnd := -1
	for _, fd := range f {
		if fd.Start < lastEnd {
			continue
		}
		selected = append(selected, fd)
		lastEnd = fd.End
	}
	// Apply right-to-left so offsets stay valid.
	out := text
	for i := len(selected) - 1; i >= 0; i-- {
		fd := selected[i]
		out = out[:fd.Start] + fmt.Sprintf("[REDACTED-%s]", fd.Label) + out[fd.End:]
	}
	return out, len(selected), nil
}
