package scanner

// Finding represents a single detected sensitive value within a scanned text.
type Finding struct {
	Label      string  `json:"label"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

// ScanResult holds all findings from a single Scan call.
type ScanResult struct {
	Findings []Finding `json:"findings"`
}
