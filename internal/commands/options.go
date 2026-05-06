package commands

import (
	"context"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/model/version"
	"github.com/oidc-mytoken/client/internal/utils/color"
)

var app = &cli.Command{
	Name:    "mytoken",
	Usage:   "Command line client for the mytoken server",
	Version: version.VERSION,
	Authors: []any{
		"Gabriel Zachmann <gabriel.zachmann@kit.edu>",
	},
	Copyright: "Karlsruhe Institute of Technology 2020-2026",
	Action: func(ctx context.Context, cmd *cli.Command) error {
		return cli.ShowAppHelp(cmd)
	},
}

var configFile string
var mytokenURL string

func init() {
	cli.RootCommandHelpTemplate = `NAME:
    {{template "helpNameTemplate" .}}

USAGE:
    {{if .UsageText}}{{wrap .UsageText 3}}{{else}}{{.FullName}} {{if .VisibleFlags}}[global options]{{end}}{{if .VisibleCommands}} [command [command options]]{{end}}{{if .ArgsUsage}} {{.ArgsUsage}}{{else}}{{if .Arguments}} [arguments...]{{end}}{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

VERSION:
    {{.Version}}{{end}}{{end}}{{if .Description}}

DESCRIPTION:
    {{template "descriptionTemplate" .}}{{end}}
{{- if len .Authors}}

AUTHOR{{template "authorsTemplate" .}}{{end}}{{if .VisibleCommands}}

COMMANDS:{{template "visibleCommandCategoryTemplate" .}}{{end}}{{if .VisibleFlagCategories}}

GLOBAL OPTIONS:{{template "visibleFlagCategoryTemplate" .}}{{else if .VisibleFlags}}

GLOBAL OPTIONS:{{template "visibleFlagTemplate" .}}{{end}}{{if .Copyright}}

COPYRIGHT:
    {{template "copyrightTemplate" .}}{{end}}

DOCUMENTATION:
        https://mytoken-docs.data.kit.edu/client/intro

CONTACT:
        m-contact@lists.kit.edu
`

	app.Flags = append(
		app.Flags, &cli.StringFlag{
			Name:  "config",
			Usage: "Load configuration from `FILE`",
			Sources: cli.EnvVars(
				"MYTOKEN_CONFIG",
				"MYTOKEN_CONF",
			),
			TakesFile:   true,
			Destination: &configFile,
		},
		&cli.StringFlag{
			Name:    "url",
			Aliases: []string{"mytoken-url"},
			Usage:   "Use the given mytoken server `URL` instead of the one from the config file",
			Sources: cli.EnvVars(
				"MYTOKEN_URL",
			),
			Destination: &mytokenURL,
		},
		&cli.BoolFlag{
			Name:  "no-color",
			Usage: "Disable colored output",
		},
	)
	app.Before = func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if cmd.IsSet("config") {
			config.Load(configFile)
		} else {
			config.LoadDefault()
		}
		if cmd.IsSet("url") {
			config.SetURL(mytokenURL)
		}
		if cmd.IsSet("no-color") {
			color.DisableColors()
		}
		return ctx, nil
	}
}

// Parse parses the command line options and calls the specified command
func Parse() {
	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
