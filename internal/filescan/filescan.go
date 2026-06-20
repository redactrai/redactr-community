package filescan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/redactrai/redactr-community/internal/scanner"
)

// Finding is one secret found in a file.
type Finding struct {
	Path  string
	Line  int
	Label string
}

const maxFileSize = 5 << 20 // 5 MB

// skipDir reports directories we never descend into.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".redactr", ".redactr-community":
		return true
	}
	return false
}

// looksBinary reports whether b appears to be binary (contains a NUL in the head).
func looksBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

// lineOf returns the 1-based line number of byte offset off in s.
func lineOf(s string, off int) int {
	if off > len(s) {
		off = len(s)
	}
	return strings.Count(s[:off], "\n") + 1
}

// Scan walks root (file or dir) and returns all findings. sc is the shared scanner.
func Scan(root string, sc *scanner.RegexScanner) ([]Finding, error) {
	var out []Finding
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > maxFileSize {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil || looksBinary(b) {
			return nil
		}
		res, err := sc.Scan(string(b))
		if err != nil {
			return nil
		}
		for _, f := range res.Findings {
			out = append(out, Finding{Path: path, Line: lineOf(string(b), f.Start), Label: f.Label})
		}
		return nil
	}
	return out, filepath.WalkDir(root, walk)
}

// RedactFile rewrites path in place with secrets redacted. Returns count redacted.
func RedactFile(path string, sc *scanner.RegexScanner) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if looksBinary(b) {
		return 0, nil
	}
	red, n, err := sc.Redact(string(b))
	if err != nil || n == 0 {
		return 0, err
	}
	info, _ := os.Stat(path)
	mode := os.FileMode(0o644)
	if info != nil {
		mode = info.Mode()
	}
	return n, os.WriteFile(path, []byte(red), mode)
}
