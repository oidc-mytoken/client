package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Songmu/prompter"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/oidc-mytoken/server/shared/utils/jwtutils"
	log "github.com/sirupsen/logrus"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/model"
)

// PTOptions holds command line options that can be used with all commands
type PTOptions struct {
	Provider    string  `short:"p" long:"provider" description:"The name or issuer url of the OpenID provider that should be used"`
	Name        string  `short:"t" long:"name" description:"The name of the mytoken that should be used"`
	Mytoken     *string `long:"MT" optional:"true" optional-value:"" description:"The passed mytoken is used instead of a stored one. If cou want to use this, please check if one of the more secure options --MT-file or --MT-env can be used"`
	MytokenFile string  `long:"MT-file" description:"Read the mytoken that should be used from the first line of the passed file"`
	MytokenEnv  string  `long:"MT-env" description:"Read the mytoken that should be used from the passed environment variable"`
}

func (g *PTOptions) Check() (*model.Provider, string) {
	token, _ := g.getToken()
	if token != "" {
		if utils.IsJWT(token) {
			g.Provider, _ = jwtutils.GetStringFromJWT(token, "oidc_iss")
		}
		p, _ := g.checkProvider("")
		return p, token
	}
	p, err := g.checkProvider(g.Name)
	if err != nil {
		log.Fatal(err)
	}
	token, err = config.Get().GetToken(p.Issuer, g.Name)
	if err != nil {
		log.Fatal(err)
	}
	return p, token
}

func (g *PTOptions) getToken() (string, error) {
	if g.Mytoken != nil {
		if *g.Mytoken != "" {
			return *g.Mytoken, nil
		}
		return prompter.Password("Enter mytoken"), nil
	}
	if g.MytokenEnv != "" {
		tok, ok := os.LookupEnv(g.MytokenEnv)
		if ok {
			return tok, nil
		}
	}
	if g.MytokenFile != "" {
		content, err := ioutil.ReadFile(g.MytokenFile)
		if err != nil {
			return "", err
		}
		return strings.SplitN(string(content), "\n", 2)[0], nil
	}
	return "", nil
}

func (g *PTOptions) checkToken(issuer string) (string, error) {
	tok, err := g.getToken()
	if err != nil || tok != "" {
		return tok, err
	}
	return config.Get().GetToken(issuer, g.Name)
}

func (g *PTOptions) checkProvider(tokenName string) (p *model.Provider, err error) {
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
