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
	MT             mtCommand
	AT             atCommand
	Revoke         revokeCommand
	Info           infoCommand
	List           listCommand
}

var parser *flags.Parser

func init() {
	options.GeneralOptions.Version = func() {
		fmt.Printf("mytoken %s\n", version.VERSION())
		os.Exit(0)
	}
	options.GeneralOptions.Config = func(filename flags.Filename) {
		if filename != "" {
			config.Load(string(filename))
		} else {
			config.LoadDefault()
		}
	}

	parser = flags.NewNamedParser("mytoken", flags.Default)
	_, _ = parser.AddGroup("Config Options", "", &options.GeneralOptions)
	_, _ = parser.AddCommand("AT", "Obtain access token", "Obtain a new OpenID Connect access token", &options.AT)
	_, _ = parser.AddCommand("revoke", "Revoke mytoken", "Revoke a mytoken token", &options.Revoke)
	_, _ = parser.AddCommand("list", "List different information", "List different information", &options.List)
	options.Info.PTOptions = &PTOptions{}
	options.Info.Introspect.PTOptions = options.Info.PTOptions
	options.Info.EventHistory.PTOptions = options.Info.PTOptions
	options.Info.SubTree.PTOptions = options.Info.PTOptions
	options.Info.TokenList.PTOptions = options.Info.PTOptions
	info, _ := parser.AddCommand("info", "Get information about a mytoken", "Get information about a mytoken", &options.Info)
	info.SubcommandsOptional = true
	mt_init()
}

// Parse parses the command line options and calls the specified command
func Parse() {
	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}
}
