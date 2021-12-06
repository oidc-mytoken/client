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
	"github.com/zachmann/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/model"
)

// PTOptions holds command line options that can be used with all commands
type PTOptions struct {
	Provider      string
	Name          string
	Mytoken       string
	MytokenPrompt bool
	MytokenFile   string
	MytokenEnv    string
}

func getPTFlags() ([]cli.Flag, *PTOptions) {
	opts := PTOptions{}
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "provider",
			Aliases:     []string{"i", "issuer"},
			Usage:       "The name or issuer url of the OpenID provider that should be used",
			EnvVars:     []string{"MYTOKEN_PROVIDER"},
			Destination: &opts.Provider,
			Placeholder: "PROVIDER",
		},
		&cli.StringFlag{
			Name:        "name",
			Aliases:     []string{"t", "n"},
			Usage:       "The `NAME` of the mytoken that should be used",
			EnvVars:     []string{"MYTOKEN_NAME"},
			Destination: &opts.Name,
		},
		&cli.StringFlag{
			Name:        "MT",
			Usage:       "The passed `MYTOKEN` is used instead of a stored one. If you want to use this, please check if one of the more secure options --MT-prompt, --MT-file or --MT-env can be used",
			Destination: &opts.Mytoken,
		},
		&cli.BoolFlag{
			Name:             "MT-prompt",
			Usage:            "If set, you are prompted for a mytoken to be passed",
			Destination:      &opts.MytokenPrompt,
			HideDefaultValue: true,
		},
		&cli.StringFlag{
			Name:        "MT-file",
			Usage:       "Read the mytoken that should be used from the first line of the passed `FILE`",
			TakesFile:   true,
			Destination: &opts.MytokenFile,
		},
		&cli.StringFlag{
			Name:        "MT-env",
			Usage:       "Read the mytoken that should be used from the passed environment variable `ENV`",
			Destination: &opts.MytokenEnv,
		},
	}
	return flags, &opts
}

func addPTFlags(cmd *cli.Command) *PTOptions {
	flags, opts := getPTFlags()
	cmd.Flags = append(cmd.Flags, flags...)
	return opts
}

func (g *PTOptions) Check() (*model.Provider, string) {
	token, _ := g.getToken()
	if token != "" {
		if utils.IsJWT(token) {
			g.Provider, _ = jwtutils.GetStringFromJWT(token, "oidc_iss")
		}
		p, _ := g.checkProvider()
		return p, token
	}
	p, err := g.checkProvider()
	if err != nil {
		log.Fatal(err)
	}
	token, err = config.Get().GetToken(p.Issuer, &g.Name)
	if err != nil {
		log.Fatal(err)
	}
	return p, token
}

func (g *PTOptions) getToken() (string, error) {
	if g.MytokenPrompt {
		return prompter.Password("Enter mytoken"), nil
	}
	if g.Mytoken != "" {
		return g.Mytoken, nil
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
	return config.Get().GetToken(issuer, &g.Name)
}

func (g *PTOptions) checkProvider() (p *model.Provider, err error) {
	if g.Provider == "" {
		issForToken, found := config.Get().TokensFileContent.TokenMapping[g.Name]
		if found && len(issForToken) > 0 {
			if len(issForToken) > 1 {
				err = fmt.Errorf("Provider not specified and token name exists for multiple providers.")
				return
			}
			g.Provider = issForToken[0]
		} else {
			g.Provider = config.Get().DefaultProvider
		}
		if g.Provider == "" {
			if len(config.Get().TokensFileContent.Tokens) != 1 {
				err = fmt.Errorf("Provider not specified and no default provider set")
				return
			}
			for provider := range config.Get().TokensFileContent.Tokens {
				// There's also one provider with an token, use that one
				g.Provider = provider
				break
			}
		}
	}
	isURL := strings.HasPrefix(g.Provider, "https://")
	pp, ok := config.Get().Providers.FindBy(g.Provider, isURL)
	if !ok && !isURL {
		err = fmt.Errorf("Provider name '%s' not found in config file. Please provide a valid provider name or the provider url.", g.Provider)
		return
	}
	return pp, nil
}
