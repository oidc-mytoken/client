package wlcgtokendiscovery

import (
	"fmt"
	"os"
	"path"
	"strings"
)

var uid int

func init() {
	uid = os.Getuid()
}

func FindToken() (t, f string) {
	t = lookInEnv()
	if t != "" {
		return
	}
	t, f = lookInEnvPointedFile()
	if t != "" {
		return
	}
	t, f = lookInXDGRuntimeDir()
	if t != "" {
		return
	}
	t, f = lookInTmpDir()
	return
}

func lookInEnv() string {
	v, _ := os.LookupEnv("BEARER_TOKEN")
	return v
}

func lookInEnvPointedFile() (string, string) {
	f, _ := os.LookupEnv("BEARER_TOKEN_FILE")
	return lookInFile(f)
}

func lookInFile(f string) (string, string) {
	if f == "" {
		return "", ""
	}
	t, _ := os.ReadFile(f)
	return strings.TrimSpace(string(t)), f
}

func lookInTokenFileInDir(dir string) (t, f string) {
	if dir == "" {
		return "", ""
	}
	ff := path.Join(dir, fmt.Sprintf("mt_u%d", uid))
	t, f = lookInFile(ff)
	if t != "" {
		return
	}
	ff = path.Join(dir, fmt.Sprintf("bt_u%d", uid))
	return lookInFile(ff)
}
func lookInXDGRuntimeDir() (string, string) {
	d, _ := os.LookupEnv("XDG_RUNTIME_DIR")
	return lookInTokenFileInDir(d)
}
func lookInTmpDir() (string, string) {
	return lookInTokenFileInDir("/tmp")
}
