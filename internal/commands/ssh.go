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
	err := fdoSSH(os.Stdout, host, command, req)
	if err != nil {
		return fmt.Errorf("SSH command failed (%s %s): %w", host, command, err)
	}
	return err
}

func doSSHReturnOutput(host, command string, req interface{}) (string, error) {
	var s strings.Builder
	err := fdoSSH(&s, host, command, req)
	return s.String(), err
}

func doSSHParseJSON[T any](host, command string, req interface{}) (*T, error) {
	resStr, err := doSSHReturnOutput(host, command, req)
	if err != nil {
		return nil, err
	}
	var res T
	if err = json.Unmarshal([]byte(resStr), &res); err != nil {
		return nil, fmt.Errorf("failed to parse SSH response: %w (output: %s)", err, resStr)
	}
	return &res, nil
}
