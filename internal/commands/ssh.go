package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/oidc-mytoken/api/v0"
)

func fdoSSH(out io.Writer, host, command string, req interface{}) error {
	var cmd *exec.Cmd
	if req == nil {
		cmd = exec.Command("ssh", host, command)
	} else {
		data, err := json.Marshal(req)
		if err != nil {
			return err
		}
		cmd = exec.Command("ssh", host, command, api.SSHMimetypeJson, fmt.Sprintf("'%s'", string(data)))
	}
	cmd.Stderr = os.Stderr
	cmd.Stdout = out
	return cmd.Run()
}

func doSSH(host, command string, req interface{}) error {
	return fdoSSH(os.Stdout, host, command, req)
}

func doSSHReturnOutput(host, command string, req interface{}) (string, error) {
	var s strings.Builder
	err := fdoSSH(&s, host, command, req)
	return s.String(), err
}
