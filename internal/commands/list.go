package commands

import (
	"fmt"
	"strings"

	"github.com/oidc-mytoken/client/internal/config"
)

// listCommand is a type for holding and handling the list command
type listCommand struct {
	ListTokens    listTokenCommand    `command:"tokens" description:"List the stored mytokens"`
	ListProviders listProviderCommand `command:"providers" description:"List the available providers"`
	// EventHistory historyCommand `command:"history" description:"List the event history for this token"`
	// SubTree      treeCommand    `command:"tree" description:"List the tree of subtokens for this token"`
}

type listTokenCommand struct{}
type listProviderCommand struct{}

// Execute implements the flags.Commander interface
func (lt *listTokenCommand) Execute(args []string) error {
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

// Execute implements the flags.Commander interface
func (lp *listProviderCommand) Execute(args []string) error {
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
