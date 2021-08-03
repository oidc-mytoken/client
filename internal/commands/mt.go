package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Songmu/prompter"
	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/oidc-mytoken/server/shared/utils/unixtime"
	"github.com/zachmann/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/cryptutils"
	"github.com/oidc-mytoken/client/internal/utils/duration"
)

var mtCommand = struct {
	*commonMTOptions

	Tag       string
	TokenType string
	Out       string
}{}

var mtStoreCommand = struct {
	*commonMTOptions
	GPGKey   string `short:"k" long:"gpg-key" value-name:"KEY" description:"Use KEY for encryption instead of the default key"`
	Password bool   `long:"password" description:"Use a password for encrypting the token instead of a gpg key."`
}{}

type commonMTOptions struct {
	*PTOptions
	TransferCode string
	UseOIDCFlow  bool

	Capabilities         api.Capabilities
	SubtokenCapabilities api.Capabilities
	Restrictions         string

	RestrictScopes        cli.StringSlice
	RestrictAudiences     cli.StringSlice
	RestrictExp           string
	RestrictNbf           string
	RestrictIP            cli.StringSlice
	RestrictGeoIPAllow    cli.StringSlice
	RestrictGeoIPDisallow cli.StringSlice
	RestrictUsagesOther   int64
	RestrictUsagesAT      int64
}

func getMTCommonFlags() ([]cli.Flag, *commonMTOptions) {
	ptFlags, ptOpts := getPTFlags()
	opts := commonMTOptions{
		PTOptions: ptOpts,
	}
	caps := make(cli.Choices)
	for _, c := range api.AllCapabilities {
		caps[c.Name] = c
	}
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "TC",
			Usage:       "Use the passed `TRANSFER_CODE` to exchange it into a mytoken",
			EnvVars:     []string{"MYTOKEN_TC"},
			Destination: &opts.TransferCode,
		},
		&cli.BoolFlag{
			Name:             "oidc",
			Usage:            "Use an OpenID Connect flow to create a mytoken",
			Destination:      &opts.UseOIDCFlow,
			HideDefaultValue: true,
		},
		// &cli.ChoiceFlag{
		// 	Name:        "flow",
		// 	Aliases:     []string{"oidc-flow"},
		// 	Value:       "default",
		// 	Choice:      cli.NewStringChoice("auth"),
		// 	Usage:       "Use the passed OpenID Connect flow to create a mytoken",
		// 	DefaultText: "from config file",
		// 	Destination: &opts.OIDCFlow,
		// 	Placeholder: "FLOW",
		// },
		&cli.ChoiceFlag{
			Name:        "capability",
			Aliases:     []string{"capabilities"},
			Choice:      cli.NewChoice(caps),
			Usage:       "Request the passed capabilities. Can be used multiple times",
			DefaultText: "from config file",
			Destination: &opts.Capabilities,
			Placeholder: "CAPABILITY",
		},
		&cli.ChoiceFlag{
			Name:        "subtoken-capability",
			Aliases:     []string{"subtoken-capabilities"},
			Choice:      cli.NewChoice(caps),
			Usage:       "Request the passed subtoken capabilities. Can be used multiple times",
			DefaultText: "from config file",
			Destination: &opts.SubtokenCapabilities,
			Placeholder: "CAPABILITY",
		},
		&cli.StringFlag{
			Name:        "restrictions",
			Aliases:     []string{"restriction"},
			Usage:       "The restrictions that restrict the requested mytoken. Can be a json object or array, or a path to a json file.'",
			EnvVars:     []string{"MYTOKEN_RESTRICTIONS", "MYTOKEN_RESTRICTION"},
			Destination: &opts.Restrictions,
			Placeholder: "RESTRICTIONS",
		},
		&cli.StringSliceFlag{
			Name:        "scope",
			Aliases:     []string{"s", "scopes"},
			Usage:       "Restrict the mytoken so that it can only be used to request ATs with these SCOPES. Can be used multiple times. Overwritten by --restriction.",
			Destination: &opts.RestrictScopes,
			Placeholder: "SCOPE",
		},
		&cli.StringSliceFlag{
			Name:        "aud",
			Aliases:     []string{"audience", "audiences"},
			Usage:       "Restrict the mytoken so that it can only be used to request ATs with these audiences. Can be used multiple times. Overwritten by --restriction.",
			Destination: &opts.RestrictAudiences,
			Placeholder: "AUD",
		},
		&cli.StringFlag{
			Name:        "exp",
			Aliases:     []string{"naf"},
			Usage:       "Restrict the mytoken so that it cannot be used after `EXP`. The time can be given as an absolute time given as a unix timestamp, a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'.",
			Destination: &opts.RestrictExp,
		},
		&cli.StringFlag{
			Name:        "nbf",
			Usage:       "Restrict the mytoken so that it cannot be used before `NBF`. The time can be given as an absolute time given as a unix timestamp, a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'.",
			Destination: &opts.RestrictNbf,
		},
		&cli.StringSliceFlag{
			Name:        "ip",
			Aliases:     []string{"ips", "ip-allow"},
			Usage:       "Restrict the mytoken so that it can only be used from these IPs. Can be a network address block or a single ip.",
			Destination: &opts.RestrictIP,
			Placeholder: "IP",
		},
		&cli.StringSliceFlag{
			Name:        "geo-ip-allow",
			Usage:       "Restrict the mytoken so that it can be only used from these COUNTRIES. Must be a short country code, e.g. 'us'.",
			Destination: &opts.RestrictIP,
			Placeholder: "COUNTRY",
		},
		&cli.StringSliceFlag{
			Name:        "geo-ip-disallow",
			Usage:       "Restrict the mytoken so that it cannot be used from these COUNTRIES. Must be a short country code, e.g. 'us'.",
			Destination: &opts.RestrictIP,
			Placeholder: "COUNTRY",
		},
		&cli.Int64Flag{
			Name:        "usages-AT",
			Aliases:     []string{"usages-at"},
			Usage:       "Restrict how often the mytoken can be used for requesting an access token.",
			DefaultText: "infinite",
			Destination: &opts.RestrictUsagesAT,
			Placeholder: "NUM",
		},
		&cli.Int64Flag{
			Name:        "usages-other",
			Usage:       "Restrict how often the mytoken can be used for actions other than requesting an access token.",
			DefaultText: "infinite",
			Destination: &opts.RestrictUsagesOther,
			Placeholder: "NUM",
		},
	}
	flags = append(ptFlags, flags...)
	return flags, &opts
}

func init() {
	mtFlags, opts := getMTCommonFlags()
	mtCommand.commonMTOptions = opts
	cmd :=
		&cli.Command{
			Name:   "MT",
			Usage:  "Obtain a mytoken",
			Action: obtainMTCmd,
			Flags: append(mtFlags,
				&cli.StringFlag{
					Name:        "tag",
					Usage:       "A name for the returned mytoken; used for finding the token in a list of mytokens.",
					Destination: &mtCommand.Tag,
					Placeholder: "NAME",
				},
				&cli.ChoiceFlag{
					Name:        "token-type",
					Usage:       "The type of the returned token. Can only be used if token is not stored.",
					Value:       "token",
					Choice:      cli.NewStringChoice("token", "short", "transfer"),
					Destination: &mtCommand.TokenType,
					Placeholder: "TYPE",
				},
				&cli.StringFlag{
					Name:        "out",
					Aliases:     []string{"o"},
					Usage:       "The mytoken will be printed to this output",
					Value:       "/dev/stdout",
					Destination: &mtCommand.Out,
					Placeholder: "FILE",
				},
			),
		}
	app.Commands = append(app.Commands, cmd)
	initStore(cmd)
}

func initStore(cmd *cli.Command) {
	mtFlags, opts := getMTCommonFlags()
	mtStoreCommand.commonMTOptions = opts
	cmd.Subcommands = append(cmd.Subcommands, &cli.Command{
		Name:      "store",
		Usage:     "Store the obtained mytoken encrypted instead of returning it. This way the mytoken can be easily used with mytoken.",
		Action:    storeMTCmd,
		ArgsUsage: "STORE_NAME",
		Flags: append(mtFlags,
			&cli.StringFlag{
				Name:        "gpg-key",
				Aliases:     []string{"k"},
				Usage:       "Use `KEY` for encryption instead of the default key",
				Destination: &mtStoreCommand.GPGKey,
			},
			&cli.BoolFlag{
				Name:        "password",
				Usage:       "Use a password for encrypting the token instead of a gpg key.",
				Destination: &mtStoreCommand.Password,
			},
		),
	})
}

func obtainMTCmd(context *cli.Context) error {
	mtc := mtCommand
	if len(mtc.Capabilities) == 0 {
		mtc.Capabilities = api.NewCapabilities(config.Get().DefaultTokenCapabilities.Returned)
	}

	st, err := obtainMT(context, mtc.commonMTOptions, mtc.Tag, mtc.TokenType)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(mtc.Out, append([]byte(st), '\n'), 0600)
}

func obtainMT(context *cli.Context, args *commonMTOptions, name, responseType string) (string, error) {
	mytoken := config.Get().Mytoken
	if args.TransferCode != "" {
		return mytoken.GetMytokenByTransferCode(args.TransferCode)
	}
	provider, err := args.PTOptions.checkProvider(args.Name)
	if err != nil {
		return "", err
	}
	tokenName := name
	prefix := config.Get().TokenNamePrefix
	if name != "" && prefix != "" {
		tokenName = fmt.Sprintf("%s:%s", prefix, name)
	}
	var r api.Restrictions
	if args.Restrictions != "" {
		r, err = parseRestrictionOption(args.Restrictions)
		if err != nil {
			return "", err
		}
	} else {
		nbf, err := parseTime(args.RestrictNbf)
		if err != nil {
			return "", err
		}
		exp, err := parseTime(args.RestrictExp)
		if err != nil {
			return "", err
		}
		rr := api.Restriction{
			NotBefore:     nbf,
			ExpiresAt:     exp,
			Scope:         strings.Join(args.RestrictScopes.Value(), " "),
			Audiences:     args.RestrictAudiences.Value(),
			IPs:           args.RestrictIP.Value(),
			GeoIPAllow:    args.RestrictGeoIPAllow.Value(),
			GeoIPDisallow: args.RestrictGeoIPDisallow.Value(),
		}
		if context.IsSet("usages-AT") {
			rr.UsagesAT = utils.NewInt64(args.RestrictUsagesAT)
		}
		if context.IsSet("usages-other") {
			rr.UsagesOther = utils.NewInt64(args.RestrictUsagesOther)
		}
		r = api.Restrictions{rr}
	}
	if args.UseOIDCFlow /*|| args.OIDCFlow!=""*/ {
		// if args.OIDCFlow == "" {
		// 	args.OIDCFlow = config.Get().DefaultOIDCFlow
		// }
		// switch args.OIDCFlow {
		// case "auth":
		callbacks := mytokenlib.PollingCallbacks{
			Init: func(authorizationURL string) error {
				fmt.Fprintln(os.Stderr, "Using any device please visit the following url to continue:")
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, authorizationURL)
				fmt.Fprintln(os.Stderr)
				return nil
			},
			Callback: func(interval int64, iteration int) {
				if iteration == 0 {
					fmt.Fprint(os.Stderr, "Starting polling ...")
					return
				}
				if int64(iteration)%(15/interval) == 0 { // every 15s
					fmt.Fprint(os.Stderr, ".")
				}
			},
			End: func() {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "success")
			},
		}
		return mytoken.GetMytokenByAuthorizationFlow(provider.Issuer, r, args.Capabilities, args.SubtokenCapabilities, responseType, tokenName, callbacks)
		// case "device":
		// 	return "", fmt.Errorf("Not yet implemented")
		// default:
		// 	return "", fmt.Errorf("Unknown oidc flow. Implementation error.")
		// }
	}
	mtGrant, err := args.PTOptions.checkToken(provider.Issuer)
	if err != nil {
		return "", err
	}
	return mytoken.GetMytokenByMytoken(mtGrant, provider.Issuer, r, args.Capabilities, args.SubtokenCapabilities, responseType, tokenName)
}

func storeMTCmd(context *cli.Context) error {
	if context.Args().Len() == 0 {
		return fmt.Errorf("Required argument STORE_NAME is missing.")
	}
	storeName := context.Args().Get(0)
	smtc := mtStoreCommand
	if len(smtc.Capabilities) == 0 {
		smtc.Capabilities = api.NewCapabilities(config.Get().DefaultTokenCapabilities.Stored)
	}
	provider, err := smtc.commonMTOptions.PTOptions.checkProvider(smtc.Name)
	if err != nil {
		return err
	}
	if config.Get().TokensFileContent.Has(storeName, provider.Issuer) {
		pStr := provider.Name
		if pStr == "" {
			pStr = provider.Issuer
		}
		if !prompter.YN(fmt.Sprintf("A token with the name '%s' is already stored for the provider '%s'. Do you want to overwrite it?", storeName, pStr), false) {
			os.Exit(1)
		}
	}
	st, err := obtainMT(context, smtc.commonMTOptions, storeName, api.ResponseTypeToken)
	if err != nil {
		return err
	}
	gpgKey := smtc.GPGKey
	if smtc.Password {
		gpgKey = ""
	} else if gpgKey == "" {
		gpgKey = provider.GPGKey
	}
	var encryptedToken string
	if gpgKey == "" {
		encryptedToken, err = cryptutils.EncryptPassword(st)
	} else {
		encryptedToken, err = cryptutils.EncryptGPG(st, gpgKey)
	}
	if err != nil {
		return err
	}
	if err = saveEncryptedToken(encryptedToken, provider.Issuer, storeName, gpgKey); err != nil {
		return err
	}
	fmt.Printf("Saved mytoken '%s'\n", storeName)
	return nil
}

func saveEncryptedToken(token, issuer, name, gpgKey string) error {
	config.Get().TokensFileContent.Add(config.TokenEntry{
		Token:  token,
		Name:   name,
		GPGKey: gpgKey,
	}, issuer)
	return config.Get().TokensFileContent.Save()
}

type pRestriction struct {
	api.Restriction
	NotBefore string `json:"nbf,omitempty"`
	ExpiresAt string `json:"exp,omitempty"`
}

type restriction api.Restriction

func parseRestrictionOption(arg string) (api.Restrictions, error) {
	if arg == "" {
		return nil, nil
	}
	if arg[0] == '[' || arg[0] == '{' {
		return parseRestrictions(arg)
	}
	data, err := ioutil.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	return parseRestrictions(string(data))
}

func parseRestrictions(str string) (api.Restrictions, error) {
	str = strings.TrimSpace(str)
	switch str[0] {
	case '[': // multiple restrictions
		var rs []restriction
		err := json.Unmarshal([]byte(str), &rs)
		r := api.Restrictions{}
		for _, rr := range rs {
			r = append(r, api.Restriction(rr))
		}
		return r, err
	case '{': // single restriction
		var r restriction
		err := json.Unmarshal([]byte(str), &r)
		return api.Restrictions{api.Restriction(r)}, err
	default:
		return nil, fmt.Errorf("malformed restriction")
	}
}

func (r *restriction) UnmarshalJSON(data []byte) error {
	rr := pRestriction{}
	if err := json.Unmarshal(data, &rr); err != nil {
		return err
	}
	t, err := parseTime(rr.ExpiresAt)
	if err != nil {
		return err
	}
	rr.Restriction.ExpiresAt = t
	t, err = parseTime(rr.NotBefore)
	if err != nil {
		return err
	}
	rr.Restriction.NotBefore = t
	*r = restriction(rr.Restriction)
	return nil
}

func parseTime(t string) (int64, error) {
	if t == "" {
		return 0, nil
	}
	i, err := strconv.ParseInt(t, 10, 64)
	if err == nil {
		if t[0] == '+' {
			return int64(unixtime.InSeconds(i)), nil
		}
		return i, nil
	}
	if t[0] == '+' {
		d, err := duration.ParseDuration(t[1:])
		return int64(unixtime.New(time.Now().Add(d))), err
	}
	tt, err := time.ParseInLocation("2006-01-02 15:04", t, time.Local)
	return int64(unixtime.New(tt)), err
}
