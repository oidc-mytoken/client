package commands

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

func init() {
	cmd :=
		&cli.Command{
			Name:  "list",
			Usage: "List different information",
			Subcommands: []*cli.Command{
				{
					Name:    "providers",
					Aliases: []string{"issuers"},
					Usage:   "List the available providers",
					Action:  listProviders,
				},
			},
		}
	app.Commands = append(app.Commands, cmd)
}

func listProviders(_ *cli.Context) error {
	defaultProvider := config.Get().DefaultProvider
	instanceProviders := config.Get().Mytoken().ServerMetadata.ProvidersSupported
	urlMaxLen := 0
	for _, ip := range instanceProviders {
		length := len(ip.Issuer)
		if length > urlMaxLen {
			urlMaxLen = length
		}
	}
	pNamesForIssuer := make(map[string]string)
	for n, i := range config.Get().Providers {
		pNamesForIssuer[i] = n
	}
	fmt.Printf("The connected mytoken instance ('%s') supports the following providers:\n", config.Get().URL)
	for _, ip := range instanceProviders {
		url := ip.Issuer
		p, found := pNamesForIssuer[url]
		if !found {
			fmt.Println(url)
			continue
		}
		configName := p
		defaultMark := ""
		if configName == defaultProvider {
			defaultMark = " (default)"
		}
		spacing := strings.Repeat(" ", urlMaxLen-len(url))
		fmt.Printf("%s %s-> %s%s\n", url, spacing, configName, defaultMark)
	}
	return nil
}
