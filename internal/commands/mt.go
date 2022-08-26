package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	cutils "github.com/oidc-mytoken/client/internal/utils"
)

type restrictionOpts struct {
	Restrictions          string
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

type mtOpts struct {
	MTOptions
	TransferCode string
	UseOIDCFlow  bool
	Provider     string

	Capabilities         api.Capabilities
	SubtokenCapabilities api.Capabilities

	restrictionOpts

	RotationStr string
	RotationObj api.Rotation

	Name      string
	TokenType string
	Out       string
}

var mtCommand mtOpts

func (opts mtOpts) getProvider() (string, error) {
	if opts.Provider == "" {
		opts.Provider = config.Get().DefaultProvider
		if opts.Provider == "" {
			return "", fmt.Errorf("Provider not specified and no default provider set")
		}
	}
	if isURL := strings.HasPrefix(opts.Provider, "https://"); isURL {
		return opts.Provider, nil
	}
	pp, ok := config.Get().Providers[opts.Provider]
	if !ok {
		return "", fmt.Errorf(
			"Provider name '%s' not found in config file. Please provide a valid provider name or the provider url.",
			opts.Provider,
		)
	}
	return pp, nil
}
func (opts *mtOpts) parseRotationOption() error {
	rotStr := opts.RotationStr
	if rotStr == "" {
		return nil
	}
	if rotStr[0] == '{' {
		return json.Unmarshal([]byte(rotStr), &opts.RotationObj)
	}
	data, err := ioutil.ReadFile(rotStr)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &opts.RotationObj)
}

func (opts mtOpts) Rotation() *api.Rotation {
	rot := opts.RotationObj
	if rot.OnAT {
		return &rot
	}
	if rot.OnOther {
		return &rot
	}
	if rot.AutoRevoke {
		return &rot
	}
	if rot.Lifetime > 0 {
		return &rot
	}
	return nil
}

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
func getRotationFlags(rotStr *string, rot *api.Rotation) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "rotation",
			Aliases:     []string{"rotate"},
			Usage:       "The rotation policy for the requested mytoken. Can be a json object or a path to a json file.'",
			EnvVars:     []string{"MYTOKEN_ROTATION"},
			Destination: rotStr,
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
			Destination:      &rot.OnAT,
			HideDefaultValue: true,
		},
		&cli.BoolFlag{
			Name:             "rotation-on-other",
			Aliases:          []string{"rotate-on-other"},
			Usage:            "Rotate this mytoken when it is used for actions other than obtaining access tokens",
			Destination:      &rot.OnOther,
			HideDefaultValue: true,
		},
		&cli.BoolFlag{
			Name: "rotation-auto-revoke",
			Usage: "If set, " +
				"the mytoken and all it subtokens are automatically revoked when a potential abuse is detected",
			Destination:      &rot.AutoRevoke,
			HideDefaultValue: true,
		},
		&cli.Uint64Flag{
			Name:        "rotation-lifetime",
			Usage:       "Restrict the lifetime of a single rotated mytoken; given in seconds",
			DefaultText: "infinite",
			Destination: &rot.Lifetime,
			Placeholder: "LIFETIME",
		},
	}
}

func init() {
	flags := append(
		getRestrFlags(&mtCommand.restrictionOpts),
		&cli.StringFlag{
			Name:        "TC",
			Usage:       "Use the passed `TRANSFER_CODE` to exchange it into a mytoken",
			EnvVars:     []string{"MYTOKEN_TC"},
			Destination: &mtCommand.TransferCode,
		},
		&cli.BoolFlag{
			Name:             "oidc",
			Usage:            "Use an OpenID Connect flow to create a mytoken",
			Destination:      &mtCommand.UseOIDCFlow,
			HideDefaultValue: true,
		},
		&cli.StringFlag{
			Name: "provider",
			Aliases: []string{
				"i",
				"issuer",
			},
			Usage: "The name or issuer url of the OpenID provider that should be used; only needed if mytoken is" +
				" obtained through OIDC",
			EnvVars:     []string{"MYTOKEN_PROVIDER"},
			Destination: &mtCommand.Provider,
			Placeholder: "PROVIDER",
		},
		getCapabilityFlag(&mtCommand.Capabilities),
		getSubtokenCapabilityFlag(&mtCommand.SubtokenCapabilities),
	)
	flags = append(flags, getRotationFlags(&mtCommand.RotationStr, &mtCommand.RotationObj)...)
	flags = append(
		flags,
		&cli.StringFlag{
			Name:        "name",
			Aliases:     []string{"n"},
			Usage:       "A name for the returned mytoken; used for finding the token in a list of mytokens.",
			Destination: &mtCommand.Name,
			Placeholder: "NAME",
		},
		&cli.ChoiceFlag{
			Name:        "token-type",
			Usage:       "The type of the returned token.",
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
	)
	app.Commands = append(
		app.Commands, &cli.Command{
			Name: "MT",
			Aliases: []string{
				"mt",
				"mytoken",
			},
			Usage:  "Obtain a mytoken",
			Action: obtainMTCmd,
			Flags:  appendMTFlags(flags...),
		},
	)
}

func obtainMTCmd(context *cli.Context) error {
	if len(mtCommand.Capabilities) == 0 {
		mtCommand.Capabilities = api.NewCapabilities(config.Get().DefaultTokenCapabilities)
	}

	mt, err := obtainMT(context)
	if err != nil {
		return err
	}
	return os.WriteFile(mtCommand.Out, append([]byte(mt), '\n'), 0600)
}

func parseRestrictionOpts(opts *restrictionOpts, ctx *cli.Context) (r api.Restrictions, err error) {
	if opts.Restrictions != "" {
		r, err = parseRestrictionOption(opts.Restrictions)
		if err != nil {
			return
		}
		return
	}
	nbf, err := cutils.ParseTime(opts.RestrictNbf)
	if err != nil {
		return
	}
	exp, err := cutils.ParseTime(opts.RestrictExp)
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

func obtainMT(context *cli.Context) (string, error) {
	mytoken := config.Get().Mytoken
	if mtCommand.TransferCode != "" {
		return mytoken.Mytoken.FromTransferCode(mtCommand.TransferCode)
	}

	tokenName := mtCommand.Name
	prefix := config.Get().TokenNamePrefix
	if tokenName != "" && prefix != "" {
		tokenName = fmt.Sprintf("%s:%s", prefix, tokenName)
	}
	if err := mtCommand.parseRotationOption(); err != nil {
		return "", err
	}
	r, err := parseRestrictionOpts(&mtCommand.restrictionOpts, context)
	if err != nil {
		return "", err
	}
	if ssh := mtCommand.SSH(); ssh != "" {
		req := api.GeneralMytokenRequest{
			GrantType:            api.GrantTypeSSH,
			Restrictions:         r,
			Capabilities:         mtCommand.Capabilities,
			SubtokenCapabilities: mtCommand.SubtokenCapabilities,
			Name:                 tokenName,
			ResponseType:         mtCommand.TokenType,
			Rotation:             mtCommand.Rotation(),
		}
		mt, err := doSSHReturnOutput(ssh, api.SSHRequestMytoken, req)
		if mt != "" && mt[len(mt)-1] == '\n' {
			mt = mt[:len(mt)-1]
		}
		return mt, err
	}
	mtGrant := mtCommand.GetToken(&mtCommand.Provider)
	if mtGrant != "" && !mtCommand.UseOIDCFlow {
		mtRes, err := mytoken.Mytoken.APIFromMytoken(
			mtGrant, mtCommand.Provider, r, mtCommand.Capabilities,
			mtCommand.SubtokenCapabilities, mtCommand.Rotation(),
			mtCommand.TokenType, tokenName,
		)
		if err != nil {
			return "", err
		}
		if mtRes.TokenUpdate != nil {
			updateMytoken(mtRes.TokenUpdate.Mytoken)
		}
		return mtRes.Mytoken, nil
	}

	// OIDC
	provider, err := mtCommand.getProvider()
	if err != nil {
		return "", err
	}
	callbacks := mytokenlib.PollingCallbacks{
		Init: func(authorizationURL string) error {
			_, _ = fmt.Fprintln(os.Stderr, "Using any device please visit the following url to continue:")
			_, _ = fmt.Fprintln(os.Stderr)
			_, _ = fmt.Fprintln(os.Stderr, authorizationURL)
			_, _ = fmt.Fprintln(os.Stderr)
			return nil
		},
		Callback: func(interval int64, iteration int) {
			if iteration == 0 {
				_, _ = fmt.Fprint(os.Stderr, "Starting polling ...")
				return
			}
			if int64(iteration)%(15/interval) == 0 { // every 15s
				_, _ = fmt.Fprint(os.Stderr, ".")
			}
		},
		End: func() {
			_, _ = fmt.Fprintln(os.Stderr)
			_, _ = fmt.Fprintln(os.Stderr, "success")
		},
	}
	return mytoken.Mytoken.FromAuthorizationFlow(
		provider, r, mtCommand.Capabilities,
		mtCommand.SubtokenCapabilities, mtCommand.Rotation(), mtCommand.TokenType,
		tokenName, callbacks,
	)
}

func parseRestrictionOption(arg string) (api.Restrictions, error) {
	if arg == "" {
		return nil, nil
	}
	if arg[0] == '[' || arg[0] == '{' {
		return parseRestrictions(arg)
	}
	data, err := os.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	return parseRestrictions(string(data))
}

func parseRestrictions(str string) (api.Restrictions, error) {
	str = strings.TrimSpace(str)
	switch str[0] {
	case '[': // multiple restrictions
		var rs []cutils.APIRestriction
		err := json.Unmarshal([]byte(str), &rs)
		r := api.Restrictions{}
		for _, rr := range rs {
			tmp := api.Restriction(rr)
			r = append(r, &tmp)
		}
		return r, err
	case '{': // single restriction
		var r cutils.APIRestriction
		err := json.Unmarshal([]byte(str), &r)
		tmp := api.Restriction(r)
		return api.Restrictions{&tmp}, err
	default:
		return nil, fmt.Errorf("malformed restriction")
	}
}
