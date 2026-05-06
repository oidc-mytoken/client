package color

import (
	"fmt"
	"strings"
)

// NamedColorMap maps HTML color names to hex codes
var NamedColorMap = map[string]string{
	"red":       "#FF0000",
	"blue":      "#0000FF",
	"green":     "#008000",
	"yellow":    "#FFFF00",
	"orange":    "#FFA500",
	"purple":    "#800080",
	"pink":      "#FFC0CB",
	"cyan":      "#00FFFF",
	"magenta":   "#FF00FF",
	"lime":      "#00FF00",
	"teal":      "#008080",
	"navy":      "#000080",
	"maroon":    "#800000",
	"olive":     "#808000",
	"silver":    "#C0C0C0",
	"gray":      "#808080",
	"grey":      "#808080",
	"black":     "#000000",
	"white":     "#FFFFFF",
	"darkgray":  "#A9A9A9",
	"darkgrey":  "#A9A9A9",
	"lightgray": "#D3D3D3",
	"lightgrey": "#D3D3D3",
	"gold":      "#FFD700",
	"brown":     "#A52A2A",
	"coral":     "#FF7F50",
	"crimson":   "#DC143C",
	"indigo":    "#4B0082",
	"ivory":     "#FFFFF0",
	"khaki":     "#F0E68C",
	"lavender":  "#E6E6FA",
	"salmon":    "#FA8072",
	"tan":       "#D2B48C",
	"tomato":    "#FF6347",
	"violet":    "#EE82EE",
	"wheat":     "#F5DEB3",
}

// NormalizeColor converts a color string (hex or named) to hex format
func NormalizeColor(color string) (string, error) {
	color = strings.ToLower(strings.TrimSpace(color))

	// Check if it's a named color
	if hex, ok := NamedColorMap[color]; ok {
		return hex, nil
	}

	// Validate hex format (#RRGGBB)
	if strings.HasPrefix(color, "#") && len(color) == 7 {
		return strings.ToUpper(color), nil
	}

	// Validate short hex format (#RGB)
	if strings.HasPrefix(color, "#") && len(color) == 4 {
		r := string(color[1])
		g := string(color[2])
		b := string(color[3])
		return strings.ToUpper(fmt.Sprintf("#%s%s%s%s%s%s", r, r, g, g, b, b)), nil
	}

	return "", fmt.Errorf("invalid color: %s", color)
}

// HexToRGB extracts RGB values from hex color
func HexToRGB(hex string) (r, g, b int, err error) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0, 0, 0, fmt.Errorf("invalid hex color: %s", hex)
	}

	fmt.Sscanf(hex[0:2], "%02x", &r)
	fmt.Sscanf(hex[2:4], "%02x", &g)
	fmt.Sscanf(hex[4:6], "%02x", &b)

	return r, g, b, nil
}

// TerminalColorBlock returns ANSI escape sequence for terminal color visualization
func TerminalColorBlock(hex string) string {
	if !ShouldUseColors() {
		return ""
	}
	r, g, b, err := HexToRGB(hex)
	if err != nil {
		return "[?]"
	}
	// Return ANSI true color block (two spaces for better visibility)
	return fmt.Sprintf("\x1b[48;2;%d;%d;%dm  \x1b[0m", r, g, b)
}

// PrintColoredTag prints a tag with colored indicator
func PrintColoredTag(tag, hex string) {
	colorBlock := TerminalColorBlock(hex)
	fmt.Printf("%s %s (%s)\n", colorBlock, tag, hex)
}

// FormatColoredTag returns a formatted string with colored indicator
func FormatColoredTag(tag, hex string) string {
	colorBlock := TerminalColorBlock(hex)
	return fmt.Sprintf("%s %s (%s)", colorBlock, tag, hex)
}

// ColorizeText returns ANSI escape sequence for colored text
func ColorizeText(text, hex string) string {
	if !ShouldUseColors() {
		return text
	}
	r, g, b, err := HexToRGB(hex)
	if err != nil {
		return text
	}
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, text)
}

// Italic returns ANSI escape sequence for italic text
func Italic(text string) string {
	if !ShouldUseColors() {
		return text
	}
	return fmt.Sprintf("\x1b[3m%s\x1b[0m", text)
}

// Gray returns ANSI escape sequence for gray text
func Gray(text string) string {
	if !ShouldUseColors() {
		return text
	}
	return fmt.Sprintf("\x1b[38;2;128;128;128m%s\x1b[0m", text)
}
