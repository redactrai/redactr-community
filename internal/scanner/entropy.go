package scanner

import "math"

const (
	entropyMinLen    = 20
	entropyThreshold = 3.5 // bits/char (Shannon entropy)
)

// shannonEntropy returns the Shannon entropy in bits/char for the given byte slice.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var h float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// entropyFindings tokenizes text into maximal runs of secret-safe characters and
// returns a Finding for each token that looks like a high-entropy secret.
//
// A token is flagged when ALL of:
//   - length ≥ 20 bytes
//   - Shannon entropy ≥ 3.5 bits/char
//   - contains at least 2 of {lowercase letter, uppercase letter, decimal digit}
//   - is NOT composed entirely of decimal digits
//
// Confidence is fixed at 0.6 (heuristic, not definitive).
func entropyFindings(text string) []Finding {
	var findings []Finding

	// Walk the string, extracting maximal runs of chars that appear in secrets.
	// Secret-safe chars: A-Z a-z 0-9 + / _ - = .
	start := -1
	for i := 0; i <= len(text); i++ {
		inSet := false
		if i < len(text) {
			c := text[i]
			inSet = (c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '+' || c == '/' || c == '_' ||
				c == '-' || c == '=' || c == '.'
		}
		if inSet {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				end := i
				token := text[start:end]
				if isHighEntropy([]byte(token)) {
					findings = append(findings, Finding{
						Label:      "HIGH-ENTROPY",
						Value:      token,
						Start:      start,
						End:        end,
						Confidence: 0.6,
					})
				}
				start = -1
			}
		}
	}

	return findings
}

// isHighEntropy returns true when the token meets all entropy heuristic criteria.
func isHighEntropy(tok []byte) bool {
	if len(tok) < entropyMinLen {
		return false
	}

	// Reject pure decimal digit runs (timestamps, IDs, etc.)
	allDigits := true
	for _, c := range tok {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}

	// Check character-class diversity: require at least 2 of {lower, upper, digit}.
	var hasLower, hasUpper, hasDigit bool
	for _, c := range tok {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	classes := 0
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	if classes < 2 {
		return false
	}

	// Shannon entropy gate.
	return shannonEntropy(tok) >= entropyThreshold
}
