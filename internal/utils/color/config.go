package color

import (
	"os"

	"github.com/mattn/go-isatty"
)

var colorsEnabled = true

func init() {
	// Priority 1: CLICOLOR_FORCE=1 forces colors on
	if os.Getenv("CLICOLOR_FORCE") == "1" {
		colorsEnabled = true
		return
	}

	// Priority 2: NO_COLOR disables colors (any value)
	if os.Getenv("NO_COLOR") != "" {
		colorsEnabled = false
		return
	}

	// Priority 3: CLICOLOR=0 disables colors
	if os.Getenv("CLICOLOR") == "0" {
		colorsEnabled = false
		return
	}

	// Priority 4: Not a TTY disables colors
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		colorsEnabled = false
		return
	}

	// Default: colors enabled
}

// ShouldUseColors returns true if colored output should be used
func ShouldUseColors() bool {
	return colorsEnabled
}

// DisableColors disables colored output globally
func DisableColors() {
	colorsEnabled = false
}
