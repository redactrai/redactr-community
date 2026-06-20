package cli

import "strings"

// guiTools are AI dev tools that are GUI apps (no terminal env to inherit);
// they're protected by the system proxy when the daemon is enabled, not by `run` env.
var guiTools = map[string]bool{
	"antigravity": true,
	"cursor":      true,
	"windsurf":    true,
	"code":        true, // VS Code
}

// IsGUI reports whether the given command (first token, basename) is a known GUI tool.
func IsGUI(command string) bool {
	c := command
	if i := strings.LastIndexAny(c, "/\\"); i != -1 {
		c = c[i+1:]
	}
	c = strings.ToLower(strings.TrimSuffix(c, ".exe"))
	return guiTools[c]
}
