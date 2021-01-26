package commands

import (
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/model/version"
)

type generalOptions struct {
	Config  func(filename flags.Filename) `long:"config" value-name:"FILE" default:"" description:"Use FILE as the config file instead of the default one."`
	Version func()                        `short:"V" long:"version" description:"Prints the version and exits."`
}

// options holds all the command line commands and their options
var options struct {
	GeneralOptions generalOptions
	ST             stCommand
	AT             atCommand
	Revoke         revokeCommand
	Info           infoCommand
}

var parser *flags.Parser

func init() {
	options.GeneralOptions.Version = func() {
		fmt.Printf("mytoken %s\n", version.VERSION)
		os.Exit(0)
	}
	options.GeneralOptions.Config = func(filename flags.Filename) {
		if len(filename) > 0 {
			config.Load(string(filename))
		} else {
			config.LoadDefault()
		}
	}

	parser = flags.NewNamedParser("mytoken", flags.Default)
	parser.AddGroup("Config Options", "", &options.GeneralOptions)
	parser.AddCommand("AT", "Obtain access token", "Obtain a new OpenID Connect access token", &options.AT)
	parser.AddCommand("revoke", "Revoke super token", "Revoke a mytoken super token", &options.Revoke)
	info, _ := parser.AddCommand("info", "Get information about a super token", "Get information about a super token", &options.Info)
	info.SubcommandsOptional = true
}

// Parse parses the command line options and calls the specified command
func Parse() {
	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}
}
