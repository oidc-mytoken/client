package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Songmu/prompter"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/oidc-mytoken/server/shared/utils/jwtutils"
	"github.com/oidc-mytoken/server/shared/utils/ternary"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

type ptOptions struct {
	Provider      string
	Mytoken       string
	MytokenPrompt bool
	MytokenFile   string
	MytokenEnv    string
	SSH           string
}

var ptOpts = []*ptOptions{}

type PTOptions struct{}

func (PTOptions) SetProvider(provider string) {
	if len(ptOpts) == 0 {
		ptOpts = make([]*ptOptions, 1)
	}
	ptOpts[0].Provider = provider
}

func (pt PTOptions) Provider() string {
	if res := pt.search(
		func(options *ptOptions) interface{} {
			return ternary.If(options.Provider != "", options.Provider, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (pt PTOptions) Mytoken() string {
	if res := pt.search(
		func(options *ptOptions) interface{} {
			return ternary.If(options.Mytoken != "", options.Mytoken, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (pt PTOptions) MytokenPrompt() bool {
	if res := pt.search(
		func(options *ptOptions) interface{} {
			return ternary.If(options.MytokenPrompt, true, nil)
		},
	); res != nil {
		return res.(bool)
	}
	return false
}

func (pt PTOptions) MytokenFile() string {
	if res := pt.search(
		func(options *ptOptions) interface{} {
			return ternary.If(options.MytokenFile != "", options.MytokenFile, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (pt PTOptions) MytokenEnv() string {
	if res := pt.search(
		func(options *ptOptions) interface{} {
			return ternary.If(options.MytokenEnv != "", options.MytokenEnv, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (pt PTOptions) SSH() string {
	if res := pt.search(
		func(options *ptOptions) interface{} {
			return ternary.If(options.SSH != "", options.SSH, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (PTOptions) search(callback func(options *ptOptions) interface{}) interface{} {
	for _, opts := range ptOpts {
		if res := callback(opts); res != nil {
			return res
		}
	}
	return nil
}

func getPTFlags() []cli.Flag {
	opts := &ptOptions{}
	ptOpts = append([]*ptOptions{opts}, ptOpts...)
	flags := []cli.Flag{
		&cli.StringFlag{
			Name: "provider",
			Aliases: []string{
				"i",
				"issuer",
			},
			Usage:       "The name or issuer url of the OpenID provider that should be used",
			EnvVars:     []string{"MYTOKEN_PROVIDER"},
			Destination: &opts.Provider,
			Placeholder: "PROVIDER",
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

		&cli.StringFlag{
			Name: "ssh",
			Usage: "Use the ssh protocol instead of a mytoken. " +
				"SSH will be passed as the first argument to the ssh client",
			Placeholder: "SSH",
			Destination: &opts.SSH,
		},
	}
	return flags
}

func (pt PTOptions) Check() (string, string) {
	token, err := pt.getToken()
	if err != nil {
		log.Fatal(err)
	}
	if utils.IsJWT(token) {
		p, _ := jwtutils.GetStringFromJWT(log.StandardLogger(), token, "oidc_iss")
		pt.SetProvider(p)
		config.Get().URL, _ = jwtutils.GetStringFromJWT(log.StandardLogger(), token, "iss")
	}
	p, _ := pt.getProvider()
	return p, token

}

func (pt PTOptions) getToken() (string, error) {
	if pt.MytokenPrompt() {
		return prompter.Password("Enter mytoken"), nil
	}
	if pt.Mytoken() != "" {
		return pt.Mytoken(), nil
	}
	if pt.MytokenEnv() != "" {
		tok, ok := os.LookupEnv(pt.MytokenEnv())
		if ok {
			return tok, nil
		}
	}
	if pt.MytokenFile() != "" {
		content, err := ioutil.ReadFile(pt.MytokenFile())
		if err != nil {
			return "", err
		}
		return strings.SplitN(string(content), "\n", 2)[0], nil
	}
	return "", nil
}

func (pt PTOptions) getProvider() (string, error) {
	if pt.Provider() == "" {
		pt.SetProvider(config.Get().DefaultProvider)
		if pt.Provider() == "" {
			return "", fmt.Errorf("Provider not specified and no default provider set")
		}
	}
	if isURL := strings.HasPrefix(pt.Provider(), "https://"); isURL {
		return pt.Provider(), nil
	}
	pp, ok := config.Get().Providers[pt.Provider()]
	if !ok {
		return "", fmt.Errorf(
			"Provider name '%s' not found in config file. Please provide a valid provider name or the provider url.",
			pt.Provider(),
		)
	}
	return pp, nil
}

func updateMytoken(updatedToken string) {
	f := PTOptions{}.MytokenFile()
	if f == "" {
		_, err := fmt.Fprintf(
			os.Stderr, "The used mytoken changed ("+
				"this indicates that token rotation is enabled for it), "+
				"but the updated mytoken cannot be stored back, because it was not passed in a file. "+
				"This is the updated mytoken:\n%s\n", updatedToken,
		)
		if err != nil {
			log.Error(err)
		}
		return
	}
	err := os.WriteFile(f, []byte(updatedToken), 0600)
	if err != nil {
		log.Error(err)
	}
}
