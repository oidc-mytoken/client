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
	"github.com/oidc-mytoken/server/shared/utils/jwtutils"
	"github.com/oidc-mytoken/server/shared/utils/unixtime"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/duration"
)

var mtCommand = struct {
	Tag       string
	TokenType string
	Out       string
}{}

var mtStoreCommand = struct {
	GPGKey   string `short:"k" long:"gpg-key" value-name:"KEY" description:"Use KEY for encryption instead of the default key"`
	Password bool   `long:"password" description:"Use a password for encrypting the token instead of a gpg key."`
}{}

func getCapabilityFlag(c *api.Capabilities) cli.Flag {
	caps := make(cli.Choices)
	for _, c := range api.AllCapabilities {
		caps[c.Name] = c
	}
	return &cli.ChoiceFlag{
		Name:        "capability",
		Aliases:     []string{"capabilities"},
		Choice:      cli.NewChoice(caps),
		Usage:       "Request the passed capabilities. Can be used multiple times",
		DefaultText: "from config file",
		Destination: c,
		Placeholder: "CAPABILITY",
	}
}

func getSubtokenCapabilityFlag(c *api.Capabilities) cli.Flag {
	caps := make(cli.Choices)
	for _, c := range api.AllCapabilities {
		caps[c.Name] = c
	}
	return &cli.ChoiceFlag{
		Name:        "subtoken-capability",
		Aliases:     []string{"subtoken-capabilities"},
		Choice:      cli.NewChoice(caps),
		Usage:       "Request the passed subtoken capabilities. Can be used multiple times",
		DefaultText: "from config file",
		Destination: c,
		Placeholder: "CAPABILITY",
	}
}

func getRestrFlags(opts *restrictionOpts) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "restrictions",
			Aliases: []string{"restriction"},
			Usage:   "The restrictions that restrict the requested mytoken. Can be a json object or array, or a path to a json file.'",
			EnvVars: []string{
				"MYTOKEN_RESTRICTIONS",
				"MYTOKEN_RESTRICTION",
			},
			Destination: &opts.Restrictions,
			Placeholder: "RESTRICTIONS",
		},
		&cli.StringSliceFlag{
			Name: "scope",
			Aliases: []string{
				"s",
				"scopes",
			},
			Usage:       "Restrict the mytoken so that it can only be used to request ATs with these SCOPES. Can be used multiple times. Overwritten by --restriction.",
			Destination: &opts.RestrictScopes,
			Placeholder: "SCOPE",
		},
		&cli.StringSliceFlag{
			Name: "aud",
			Aliases: []string{
				"audience",
				"audiences",
			},
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
			Name: "ip",
			Aliases: []string{
				"ips",
				"ip-allow",
			},
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
}

func getMTCommonFlags(store bool) []cli.Flag {
	opts := &commonMTOptions.obtainOpts
	if store {
		opts = &commonMTOptions.storeOpts
	}

	flags := append(
		getRestrFlags(&opts.restrictionOpts),
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
		getCapabilityFlag(&opts.Capabilities),
		getSubtokenCapabilityFlag(&opts.SubtokenCapabilities),
		&cli.StringFlag{
			Name:        "rotation",
			Aliases:     []string{"rotate"},
			Usage:       "The rotation policy for the requested mytoken. Can be a json object or a path to a json file.'",
			EnvVars:     []string{"MYTOKEN_ROTATION"},
			Destination: &opts.RotationStr,
			Placeholder: "ROTATION",
		},
		&cli.BoolFlag{
			Name: "rotation-on-AT",
			Aliases: []string{
				"rotate-on-AT",
				"rotate-on-at",
				"rotation-on-at",
			},
			Usage:            "Rotate this mytoken when it is used to obtain access tokens",
			Destination:      &opts.RotationObj.OnAT,
			HideDefaultValue: true,
		},
		&cli.BoolFlag{
			Name:             "rotation-on-other",
			Aliases:          []string{"rotate-on-other"},
			Usage:            "Rotate this mytoken when it is used for actions other than obtaining access tokens",
			Destination:      &opts.RotationObj.OnOther,
			HideDefaultValue: true,
		},
		&cli.BoolFlag{
			Name: "rotation-auto-revoke",
			Usage: "If set, " +
				"the mytoken and all it subtokens are automatically revoked when a potential abuse is detected",
			Destination:      &opts.RotationObj.AutoRevoke,
			HideDefaultValue: true,
		},
		&cli.Uint64Flag{
			Name:        "rotation-lifetime",
			Usage:       "Restrict the lifetime of a single rotated mytoken; given in seconds",
			DefaultText: "infinite",
			Destination: &opts.RotationObj.Lifetime,
			Placeholder: "LIFETIME",
		},
	)
	flags = append(getPTFlags(), flags...)
	return flags
}

func init() {
	cmd :=
		&cli.Command{
			Name:   "MT",
			Usage:  "Obtain a mytoken",
			Action: obtainMTCmd,
			Flags: append(
				getMTCommonFlags(false),
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
	cmd.Subcommands = append(
		cmd.Subcommands, &cli.Command{
			Name:      "store",
			Usage:     "Store the obtained mytoken encrypted instead of returning it. This way the mytoken can be easily used with mytoken.",
			Action:    storeMTCmd,
			ArgsUsage: "STORE_NAME",
			Flags: append(
				getMTCommonFlags(true),
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
		},
	)
}

func obtainMTCmd(context *cli.Context) error {
	opts := commonMTOptions.Common(false)
	if len(opts.Capabilities) == 0 {
		opts.Capabilities = api.NewCapabilities(config.Get().DefaultTokenCapabilities.Returned)
	}

	st, err := obtainMT(opts, context, mtCommand.Tag, mtCommand.TokenType)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(mtCommand.Out, append([]byte(st), '\n'), 0600)
}

func parseRestrictionOpts(opts *restrictionOpts, ctx *cli.Context) (r api.Restrictions, err error) {
	if opts.Restrictions != "" {
		r, err = parseRestrictionOption(opts.Restrictions)
		if err != nil {
			return
		}
		return
	}
	nbf, err := parseTime(opts.RestrictNbf)
	if err != nil {
		return
	}
	exp, err := parseTime(opts.RestrictExp)
	if err != nil {
		return
	}
	rr := &api.Restriction{
		NotBefore:     nbf,
		ExpiresAt:     exp,
		Scope:         strings.Join(opts.RestrictScopes.Value(), " "),
		Audiences:     opts.RestrictAudiences.Value(),
		IPs:           opts.RestrictIP.Value(),
		GeoIPAllow:    opts.RestrictGeoIPAllow.Value(),
		GeoIPDisallow: opts.RestrictGeoIPDisallow.Value(),
	}
	if ctx.IsSet("usages-AT") {
		rr.UsagesAT = utils.NewInt64(opts.RestrictUsagesAT)
	}
	if ctx.IsSet("usages-other") {
		rr.UsagesOther = utils.NewInt64(opts.RestrictUsagesOther)
	}
	r = api.Restrictions{rr}
	return
}

func obtainMT(opts commonMTOpts, context *cli.Context, name, responseType string) (string, error) {
	mytoken := config.Get().Mytoken
	if opts.TransferCode != "" {
		return mytoken.Mytoken.FromTransferCode(opts.TransferCode)
	}

	tokenName := name
	prefix := config.Get().TokenNamePrefix
	if name != "" && prefix != "" {
		tokenName = fmt.Sprintf("%s:%s", prefix, name)
	}
	if err := opts.parseRotationOption(); err != nil {
		return "", err
	}
	r, err := parseRestrictionOpts(&opts.restrictionOpts, context)
	if err != nil {
		return "", err
	}
	if ssh := opts.SSH(); ssh != "" {
		req := api.GeneralMytokenRequest{
			GrantType:            api.GrantTypeSSH,
			Restrictions:         r,
			Capabilities:         opts.Capabilities,
			SubtokenCapabilities: opts.SubtokenCapabilities,
			Name:                 tokenName,
			ResponseType:         responseType,
			Rotation:             opts.Rotation(),
		}
		mt, err := doSSHReturnOutput(ssh, api.SSHRequestMytoken, req)
		if mt != "" && mt[len(mt)-1] == '\n' {
			mt = mt[:len(mt)-1]
		}
		return mt, err
	}
	provider, err := opts.PTOptions.checkProvider()
	if err != nil {
		return "", err
	}
	if opts.UseOIDCFlow {
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
		return mytoken.Mytoken.FromAuthorizationFlow(
			provider.Issuer, r, opts.Capabilities,
			opts.SubtokenCapabilities, opts.Rotation(), responseType,
			tokenName, callbacks,
		)
	}
	mtGrant, err := opts.PTOptions.checkToken(provider.Issuer)
	if err != nil {
		return "", err
	}
	mtRes, err := mytoken.Mytoken.APIFromMytoken(
		mtGrant, provider.Issuer, r, opts.Capabilities,
		opts.SubtokenCapabilities, opts.Rotation(),
		responseType, tokenName,
	)
	if err != nil {
		return "", err
	}
	if mtRes.TokenUpdate != nil {
		config.Get().TokensFileContent.Update(
			opts.Name(), provider.Issuer,
			config.NewPlainStoreToken(mtRes.TokenUpdate.Mytoken),
		)
		if err = config.Get().TokensFileContent.Save(); err != nil {
			return mtRes.Mytoken, err
		}
	}
	return mtRes.Mytoken, nil
}

func storeMTCmd(context *cli.Context) error {
	if !context.Args().Present() {
		return fmt.Errorf("Required argument STORE_NAME is missing.")
	}
	storeName := context.Args().Get(0)
	opts := commonMTOptions.Common(true)
	if len(opts.Capabilities) == 0 {
		opts.Capabilities = api.NewCapabilities(config.Get().DefaultTokenCapabilities.Stored)
	}
	provider, err := opts.PTOptions.checkProvider()
	if err != nil {
		return err
	}
	if config.Get().TokensFileContent.Has(storeName, provider.Issuer) {
		pStr := provider.Name
		if pStr == "" {
			pStr = provider.Issuer
		}
		if !prompter.YN(
			fmt.Sprintf(
				"A token with the name '%s' is already stored for the provider '%s'. Do you want to overwrite it?",
				storeName, pStr,
			), false,
		) {
			os.Exit(1)
		}
	}
	mt, err := obtainMT(opts, context, storeName, api.ResponseTypeToken)
	if err != nil {
		return err
	}
	gpgKey := mtStoreCommand.GPGKey
	if mtStoreCommand.Password {
		gpgKey = ""
	} else if gpgKey == "" {
		gpgKey = provider.GPGKey
	}
	capabilityInterfaceSlice := jwtutils.GetValueFromJWT(log.StandardLogger(), mt, "capabilities").([]interface{})
	capabilities := api.Capabilities{}
	for _, c := range capabilityInterfaceSlice {
		capabilities = append(capabilities, api.NewCapability(c.(string)))
	}
	config.Get().TokensFileContent.Add(
		config.TokenEntry{
			Token:        config.NewPlainStoreToken(mt),
			Name:         storeName,
			GPGKey:       gpgKey,
			Capabilities: capabilities,
		}, provider.Issuer,
	)
	if err = config.Get().TokensFileContent.Save(); err != nil {
		return err
	}
	fmt.Printf("Saved mytoken '%s'\n", storeName)
	return nil
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
			tmp := api.Restriction(rr)
			r = append(r, &tmp)
		}
		return r, err
	case '{': // single restriction
		var r restriction
		err := json.Unmarshal([]byte(str), &r)
		tmp := api.Restriction(r)
		return api.Restrictions{&tmp}, err
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
