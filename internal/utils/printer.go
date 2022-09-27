package utils

import (
	"os"
)

// WriteOutput writes the output to the specified file. This works also with /dev/stdout on Windows
func WriteOutput(out, data string) error {
	outData := append([]byte(data), '\n')
	if out == os.Stdout.Name() {
		_, err := os.Stdout.Write(outData)
		return err
	}
	return os.WriteFile(out, outData, 0600)
}
