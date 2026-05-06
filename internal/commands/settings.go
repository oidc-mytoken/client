package commands

import (
	"github.com/urfave/cli/v3"
)

var settingsOptions MTOptions

func init() {
	cmd :=
		&cli.Command{
			Name:  "settings",
			Usage: "View and edit your user settings",
			Flags: getMTFlags(),
		}
	app.Commands = append(app.Commands, cmd)
	initGrants(cmd)
	initEmail(cmd)
	initTags(cmd)
}
