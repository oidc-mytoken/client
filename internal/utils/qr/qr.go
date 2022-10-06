package qr

import (
	"io"
	"os"

	"github.com/mdp/qrterminal/v3"
)

var halfConfig = qrterminal.Config{
	Level:          qrterminal.M,
	HalfBlocks:     true,
	BlackChar:      qrterminal.BLACK_BLACK,
	BlackWhiteChar: qrterminal.BLACK_WHITE,
	WhiteChar:      qrterminal.WHITE_WHITE,
	WhiteBlackChar: qrterminal.WHITE_BLACK,
	QuietZone:      1,
}

// PrintQR prints a qr code for the passed data to os.Stdout
func PrintQR(data string, border ...int) {
	FPrintQR(os.Stdout, data, border...)
}

// FPrintQR writes a qr code for the passed data to an os.Writer
func FPrintQR(writer io.Writer, data string, border ...int) {
	quietZone := 1
	if len(border) > 0 {
		quietZone = border[0]
	}
	halfConfig.QuietZone = quietZone
	halfConfig.Writer = writer
	qrterminal.GenerateWithConfig(data, halfConfig)
}
