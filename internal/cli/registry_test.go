package cli

import "testing"

func TestIsGUI(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"antigravity", true},
		{"/usr/bin/cursor", true},
		{"windsurf", true},
		{"code", true},
		{"claude", false},
		{"codex", false},
		{"node", false},
		{"python3", false},
		// Windows-style paths and .exe suffix
		{`C:\Program Files\Cursor\cursor.exe`, true},
		{"code.exe", true},
	}
	for _, tc := range cases {
		got := IsGUI(tc.input)
		if got != tc.want {
			t.Errorf("IsGUI(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
