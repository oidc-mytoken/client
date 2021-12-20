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
					Name:    "tokens",
					Aliases: []string{"MT", "mytokens"},
					Usage:   "List the stored mytokens",
					Action:  listTokens,
				},
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

func listTokens(ctx *cli.Context) error {
	for iss, tokens := range config.Get().TokensFileContent.Tokens {
		provider, found := config.Get().Providers.FindBy(iss, true)
		header := iss
		defaultToken := ""
		if found {
			header = provider.Name
			defaultToken = provider.DefaultToken
		}
		fmt.Printf("The following mytokens are stored for provider '%s':\n", header)
		for _, t := range tokens {
			defaultMark := ""
			if t.Name == defaultToken {
				defaultMark = " (default)"
			}
			fmt.Printf("%s%s\n", t.Name, defaultMark)
		}
		fmt.Println()
	}
	return nil
}

func listProviders(ctx *cli.Context) error {
	defaultProvider := config.Get().DefaultProvider
	instanceProviders := config.Get().Mytoken.ProvidersSupported
	configProviders := config.Get().Providers
	urlMaxLen := 0
	for _, ip := range instanceProviders {
		length := len(ip.Issuer)
		if length > urlMaxLen {
			urlMaxLen = length
		}
	}
	fmt.Println("The connected mytoken instance supports the following providers:")
	for _, ip := range instanceProviders {
		url := ip.Issuer
		p, found := configProviders.FindBy(url, true)
		if !found {
			fmt.Println(url)
			continue
		}
		configName := p.Name
		defaultMark := ""
		if configName == defaultProvider {
			defaultMark = " (default)"
		}
		spacing := strings.Repeat(" ", urlMaxLen-len(url))
		fmt.Printf("%s %s-> %s%s\n", url, spacing, configName, defaultMark)
	}
	return nil
}
