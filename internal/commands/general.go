package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/Songmu/prompter"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/oidc-mytoken/server/shared/utils/jwtutils"
	"github.com/oidc-mytoken/server/shared/utils/ternary"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/wlcgtokendiscovery"
)

type mtOptions struct {
	Mytoken       string
	MytokenPrompt bool
	MytokenFile   string
	MytokenEnv    string
	SSH           string
}

var theMTOpts = []*mtOptions{}

type MTOptions struct{}

func (mt MTOptions) Mytoken() string {
	if res := mt.search(
		func(options *mtOptions) interface{} {
			return ternary.If(options.Mytoken != "", options.Mytoken, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (mt MTOptions) MytokenPrompt() bool {
	if res := mt.search(
		func(options *mtOptions) interface{} {
			return ternary.If(options.MytokenPrompt, true, nil)
		},
	); res != nil {
		return res.(bool)
	}
	return false
}

func (mt MTOptions) MytokenFile() string {
	if res := mt.search(
		func(options *mtOptions) interface{} {
			return ternary.If(options.MytokenFile != "", options.MytokenFile, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (MTOptions) SetMytokenFile(f string) {
	if len(theMTOpts) == 0 {
		theMTOpts = make([]*mtOptions, 1)
	}
	theMTOpts[0].MytokenFile = f
}

func (mt MTOptions) MytokenEnv() string {
	if res := mt.search(
		func(options *mtOptions) interface{} {
			return ternary.If(options.MytokenEnv != "", options.MytokenEnv, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (mt MTOptions) SSH() string {
	if res := mt.search(
		func(options *mtOptions) interface{} {
			return ternary.If(options.SSH != "", options.SSH, nil)
		},
	); res != nil {
		return res.(string)
	}
	return ""
}

func (MTOptions) search(callback func(options *mtOptions) interface{}) interface{} {
	for _, opts := range theMTOpts {
		if res := callback(opts); res != nil {
			return res
		}
	}
	return nil
}

func getMTFlags() []cli.Flag {
	opts := &mtOptions{}
	theMTOpts = append([]*mtOptions{opts}, theMTOpts...)
	flags := []cli.Flag{
		&cli.StringFlag{
			Name: "MT",
			Usage: "Uses the passed `MYTOKEN`; Please note that other options to pass the mytoken are more" +
				" secure, e.g. --MT-prompt, --MT-file or --MT-env can be used",
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

func appendMTFlags(flags ...cli.Flag) []cli.Flag {
	return append(flags, getMTFlags()...)
}

func updateIssuersFromJWT(token string, provider ...*string) {
	if utils.IsJWT(token) {
		p, ok := jwtutils.GetStringFromJWT(log.StandardLogger(), token, "oidc_iss")
		if ok && len(provider) > 0 {
			*(provider[0]) = p
		}
		iss, ok := jwtutils.GetStringFromJWT(log.StandardLogger(), token, "iss")
		if ok {
			config.Get().URL = iss
		}
	}
}
func (mt MTOptions) GetToken(provider ...*string) string {
	token := mt._getToken()
	updateIssuersFromJWT(token, provider...)
	return token
}
func (mt MTOptions) MustGetToken(provider ...*string) string {
	token := mt._getToken()
	if token == "" {
		log.Fatal("No mytoken provided.")
	}
	updateIssuersFromJWT(token, provider...)
	return token
}

func (mt MTOptions) _getToken() string {
	if mt.MytokenPrompt() {
		return prompter.Password("Enter mytoken")
	}
	if mt.Mytoken() != "" {
		return mt.Mytoken()
	}
	if mt.MytokenEnv() != "" {
		tok, ok := os.LookupEnv(mt.MytokenEnv())
		if ok {
			return tok
		}
	}
	if mt.MytokenFile() != "" {
		content, err := os.ReadFile(mt.MytokenFile())
		if err != nil {
			log.Fatal(err)
		}
		return strings.SplitN(string(content), "\n", 2)[0]
	}
	if config.Get().UseWLCGTokenDiscovery {
		t, f := wlcgtokendiscovery.FindToken()
		mt.SetMytokenFile(f)
		return t
	}
	return ""
}

func updateMytoken(updatedToken string) {
	f := MTOptions{}.MytokenFile()
	if f == "" {
		_, err := fmt.Fprintf(
			os.Stderr, "The used mytoken changed ("+
				"this indicates that token rotation is enabled for it), "+
				"but the updated mytoken cannot be stored back, because it was not passed in a file. "+
				"This is the updated mytoken:\n%s\n\n", updatedToken,
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
