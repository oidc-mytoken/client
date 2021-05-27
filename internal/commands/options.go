package commands

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zachmann/cli/v2"
	"golang.org/x/term"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/model/version"
)

var app = &cli.App{
	Name:     "mytoken",
	Usage:    "Command line client for the mytoken server",
	Version:  version.VERSION(),
	Compiled: time.Time{},
	Authors: []*cli.Author{{
		Name:  "Gabriel Zachmann",
		Email: "gabriel.zachmann@kit.edu",
	}},
	Copyright:              "Karlsruhe Institute of Technology 2020-2021",
	UseShortOptionHandling: true,
}

var configFile string

func init() {
	cli.AppHelpTemplate = `NAME:
   {{$v := offset .Name 6}}{{wrap .Name 3}}{{if .Usage}} - {{wrap .Usage $v}}{{end}}

USAGE:
   {{if .UsageText}}{{wrap .UsageText 3}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Description}}

DESCRIPTION:
   {{wrap .Description 3}}{{end}}{{if .VisibleCommands}}

COMMANDS:{{range .VisibleCategories}}{{if .Name}}
   {{.Name}}:{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{else}}{{range .VisibleCommands}}
   {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{if .VisibleFlags}}

GLOBAL OPTIONS:
   {{range $index, $option := .VisibleFlags}}{{if $index}}
   {{end}}{{$option.String}}{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

VERSION:
   {{.Version}}{{end}}{{end}}

DOCUMENTATION: 
	https://mytoken-docs.data.kit.edu/client/intro

CONTACT: 
	m-contact@lists.kit.edu
`

	termWidth, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err == nil {
		cli.HelpWrapAt = termWidth
	}

	app.Flags = append(app.Flags, &cli.StringFlag{
		Name:        "config",
		Usage:       "Load configuration from `FILE`",
		EnvVars:     []string{"MYTOKEN_CONFIG", "MYTOKEN_CONF"},
		TakesFile:   true,
		DefaultText: "",
		Destination: &configFile,
	})
	app.Before = func(context *cli.Context) error {
		if context.IsSet("config") {
			config.Load(configFile)
		} else {
			config.LoadDefault()
		}
		return nil
	}
}

// Parse parses the command line options and calls the specified command
func Parse() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
