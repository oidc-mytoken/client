package commands

import (
	"fmt"
	"strings"

	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/oidc-mytoken/server/shared/utils/jwtutils"
	log "github.com/sirupsen/logrus"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/model"
)

// ptOptions holds command line options that can be used with all commands
type ptOptions struct {
	Provider   string `short:"p" long:"provider" description:"The name or issuer url of the OpenID provider that should be used"`
	Name       string `short:"t" long:"name" description:"The name of the super token that should be used"`
	SuperToken string `long:"ST" description:"The passed super token is used instead of a stored one"`
}

func (g *ptOptions) Check() (*model.Provider, string) {
	if len(g.SuperToken) > 0 {
		if utils.IsJWT(g.SuperToken) {
			g.Provider, _ = jwtutils.GetStringFromJWT(g.SuperToken, "oidc_iss")
		}
		p, _ := g.checkProvider("")
		return p, g.SuperToken
	}
	p, pErr := g.checkProvider(g.Name)
	if pErr != nil {
		log.Fatal(pErr)
	}
	token, tErr := config.Get().GetToken(p.Issuer, g.Name)
	if tErr != nil {
		log.Fatal(tErr)
	}
	return p, token
}

func (g *ptOptions) checkToken(issuer string) (string, error) {
	if len(g.SuperToken) > 0 {
		return g.SuperToken, nil
	}
	return config.Get().GetToken(issuer, g.Name)
}

func (g *ptOptions) checkProvider(tokenName string) (p *model.Provider, err error) {
	provider := g.Provider
	if provider == "" {
		issForToken, found := config.Get().TokensFileContent.TokenMapping[tokenName]
		if found && len(issForToken) > 0 {
			if len(issForToken) > 1 {
				err = fmt.Errorf("Provider not specified and token name exists for multiple providers.")
				return
			}
			provider = issForToken[0]
		} else {
			provider = config.Get().DefaultProvider
		}
		if provider == "" {
			if len(config.Get().TokensFileContent.Tokens) != 1 {
				err = fmt.Errorf("Provider not specified and no default provider set")
				return
			}
			for provider = range config.Get().TokensFileContent.Tokens {
				// There's also one provider with an token, use that one
				break
			}
		}
	}
	isURL := strings.HasPrefix(provider, "https://")
	pp, ok := config.Get().Providers.FindBy(provider, isURL)
	if !ok && !isURL {
		err = fmt.Errorf("Provider name '%s' not found in config file. Please provide a valid provider name or the provider url.", provider)
		return
	}
	return pp, nil
}
