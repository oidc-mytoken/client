package commands

import (
	"github.com/urfave/cli/v2"
)

var settingsOptions PTOptions

func init() {
	cmd :=
		&cli.Command{
			Name:  "settings",
			Usage: "View and edit your user settings",
			Flags: getPTFlags(),
		}
	app.Commands = append(app.Commands, cmd)
	initGrants(cmd)
}
