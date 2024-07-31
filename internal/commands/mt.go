package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/oidc-mytoken/utils/utils"
	"github.com/oidc-mytoken/utils/utils/jsonutils"
	"github.com/oidc-mytoken/utils/utils/profile"
	"github.com/oidc-mytoken/utils/utils/timerestriction"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	cutils "github.com/oidc-mytoken/client/internal/utils"
	"github.com/oidc-mytoken/client/internal/utils/qr"
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

type rotationOPts struct {
	api.Rotation
	RotationStr string
}

type profileOpts struct {
	restrictionOpts
	CapabilitiesStr string
	rotationOPts
	Name      string
	TokenType string
	provider  string
}

type mtOpts struct {
	MTOptions
	TransferCode string
	UseOIDCFlow  bool

	profile string
	profileOpts
	request *api.GeneralMytokenRequest

	Out string
}

var mtCommand mtOpts

func (opts *mtOpts) parseProviderOpt() error {
	if opts.provider == "" {
		if opts.request.Issuer != "" {
			return nil
		}
		opts.provider = config.Get().DefaultProvider
		if opts.provider == "" {
			return fmt.Errorf("Provider not specified and no default provider set")
		}
	}
	if strings.HasPrefix(opts.provider, "https://") {
		opts.request.Issuer = opts.provider
		return nil
	}
	pp, ok := config.Get().Providers[opts.provider]
	if !ok {
		return fmt.Errorf(
			"Provider name '%s' not found in config file. Please provide a valid provider name or the provider url.",
			opts.provider,
		)
	}
	opts.request.Issuer = pp
	return nil
}

func (opts *mtOpts) parseCapabilitiesOption() error {
	if opts.CapabilitiesStr == "" {
		return nil
	}
	c, err := profile.ProfileParser{}.ParseCapabilityTemplate([]byte(opts.CapabilitiesStr))
	if err != nil {
		return err
	}
	if len(c) != 0 {
		opts.request.Capabilities = c
	}
	return nil
}

func (opts *mtOpts) parseRotationOption() error {
	rotStr := opts.RotationStr
	if rotStr == "" {
		return nil
	}
	rotBytes := []byte(rotStr)
	if jsonutils.IsJSONObject(rotBytes) {
		if err := json.Unmarshal(rotBytes, opts.request.Rotation); err != nil {
			return err
		}
	} else {
		opts.request.Rotation = &api.Rotation{IncludedProfiles: strings.Split(rotStr, " ")}
	}
	opts.request.Rotation.OnAT = opts.request.Rotation.OnAT || opts.OnAT
	opts.request.Rotation.OnOther = opts.request.Rotation.OnOther || opts.OnOther
	opts.request.Rotation.AutoRevoke = opts.request.Rotation.AutoRevoke || opts.AutoRevoke
	if opts.Lifetime != 0 {
		opts.request.Rotation.Lifetime = opts.Lifetime
	}
	return nil
}

func parseRestrictionOpts(rOpts restrictionOpts, ctx *cli.Context) (api.Restrictions, error) {
	mto := mtOpts{
		profileOpts: profileOpts{
			restrictionOpts: rOpts,
		},
		request: &api.GeneralMytokenRequest{},
	}
	err := mto.parseRestrictionOpts(ctx)
	if err != nil {
		return nil, err
	}
	return mto.request.Restrictions, nil
}

func (opts *mtOpts) parseRestrictionOpts(ctx *cli.Context) (err error) {
	if opts.Restrictions != "" {
		rBytes := []byte(opts.Restrictions)
		if jsonutils.IsJSONObject(rBytes) {
			rBytes = append([]byte{'['}, append(rBytes, ']')...)
		}
		if jsonutils.IsJSONArray(rBytes) {
			if err = json.Unmarshal(rBytes, &opts.request.Restrictions); err != nil {
				return
			}
		} else {
			opts.request.Restrictions = api.Restrictions{
				{
					IncludedProfiles: strings.Split(opts.Restrictions, " "),
				},
			}
		}
		return
	}
	nbf, err := timerestriction.ParseTime(opts.RestrictNbf)
	if err != nil {
		return
	}
	exp, err := timerestriction.ParseTime(opts.RestrictExp)
	if err != nil {
		return
	}
	rr := &api.Restriction{
		NotBefore:     nbf,
		ExpiresAt:     exp,
		Scope:         strings.Join(opts.RestrictScopes.Value(), " "),
		Audiences:     opts.RestrictAudiences.Value(),
		Hosts:         opts.RestrictIP.Value(),
		GeoIPAllow:    opts.RestrictGeoIPAllow.Value(),
		GeoIPDisallow: opts.RestrictGeoIPDisallow.Value(),
	}
	if ctx.IsSet("usages-AT") {
		rr.UsagesAT = utils.NewInt64(opts.RestrictUsagesAT)
	}
	if ctx.IsSet("usages-other") {
		rr.UsagesOther = utils.NewInt64(opts.RestrictUsagesOther)
	}
	if rr.UsagesAT != nil || rr.UsagesOther != nil || rr.NotBefore != 0 || rr.ExpiresAt != 0 || rr.Scope != "" ||
		len(rr.Audiences) != 0 || len(rr.Hosts) != 0 || len(rr.GeoIPAllow) != 0 || len(rr.GeoIPAllow) != 0 {
		opts.request.Restrictions = api.Restrictions{rr}
	}
	return
}

func (opts *mtOpts) Request(ctx *cli.Context) (*api.GeneralMytokenRequest, error) {
	if opts.request != nil {
		return opts.request, nil
	}
	opts.request = &api.GeneralMytokenRequest{}
	if opts.profile != "" {
		bProf := []byte(opts.profile)
		if jsonutils.IsJSONObject(bProf) {
			if err := json.Unmarshal(bProf, &opts.request); err != nil {
				return nil, err
			}
		} else {
			opts.request.IncludedProfiles = strings.Split(opts.profile, " ")
		}
	}
	if opts.Name != "" {
		opts.request.Name = opts.Name
	}
	if opts.TokenType != "" {
		switch opts.TokenType {
		case cmdArgTokenTypeShort:
			opts.request.ResponseType = api.ResponseTypeShortToken
		case cmdArgTokenTypeTransfer:
			opts.request.ResponseType = api.ResponseTypeTransferCode
		default:
			opts.request.ResponseType = opts.TokenType
		}
	}
	err := opts.parseRotationOption()
	if err != nil {
		return nil, err
	}
	err = opts.parseRestrictionOpts(ctx)
	if err != nil {
		return nil, err
	}
	err = opts.parseCapabilitiesOption()
	if err != nil {
		return nil, err
	}
	if len(opts.request.Capabilities) == 0 && len(opts.request.IncludedProfiles) == 0 {
		opts.request.Capabilities = api.NewCapabilities(config.Get().DefaultTokenCapabilities)
	}
	return opts.request, nil
}

func getCapabilityFlag(c *string) cli.Flag {
	return &cli.StringFlag{
		Name:        "capability",
		Aliases:     []string{"capabilities"},
		Usage:       "Request the passed capabilities.",
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
			Usage: "The restrictions that restrict the requested mytoken. " +
				"Can be a json object or array, or a path to a json file.'",
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
			Usage: "Restrict the mytoken so that it can only be used to request ATs with these SCOPES. " +
				"Can be used multiple times. Overwritten by --restriction.",
			Destination: &opts.RestrictScopes,
			Placeholder: "SCOPE",
		},
		&cli.StringSliceFlag{
			Name: "aud",
			Aliases: []string{
				"audience",
				"audiences",
			},
			Usage: "Restrict the mytoken so that it can only be used to request ATs with these audiences. " +
				"Can be used multiple times. Overwritten by --restriction.",
			Destination: &opts.RestrictAudiences,
			Placeholder: "AUD",
		},
		&cli.StringFlag{
			Name:    "exp",
			Aliases: []string{"naf"},
			Usage: "Restrict the mytoken so that it cannot be used after `EXP`. " +
				"The time can be given as an absolute time given as a unix timestamp, " +
				"a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'.",
			Destination: &opts.RestrictExp,
		},
		&cli.StringFlag{
			Name: "nbf",
			Usage: "Restrict the mytoken so that it cannot be used before `NBF`. " +
				"The time can be given as an absolute time given as a unix timestamp, " +
				"a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'.",
			Destination: &opts.RestrictNbf,
		},
		&cli.StringSliceFlag{
			Name: "host",
			Aliases: []string{
				"ip",
				"ips",
				"ip-allow",
				"hosts",
			},
			Usage: "Restrict the mytoken so that it can only be used from these hosts. " +
				"Can be a network address block, a single ip, or a host name.",
			Destination: &opts.RestrictIP,
			Placeholder: "IP",
		},
		&cli.StringSliceFlag{
			Name: "geo-ip-allow",
			Usage: "Restrict the mytoken so that it can be only used from these COUNTRIES. " +
				"Must be a short country code, e.g. 'us'.",
			Destination: &opts.RestrictGeoIPAllow,
			Placeholder: "COUNTRY",
		},
		&cli.StringSliceFlag{
			Name: "geo-ip-disallow",
			Usage: "Restrict the mytoken so that it cannot be used from these COUNTRIES. " +
				"Must be a short country code, e.g. 'us'.",
			Destination: &opts.RestrictGeoIPDisallow,
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

const (
	cmdArgTokenTypeShort    = "short"
	cmdArgTokenTypeTransfer = "transfer"
)

func init() {
	flags := append(
		append(
			[]cli.Flag{
				&cli.StringFlag{
					Name:  "profile",
					Usage: "A mytoken profile describing the properties of the mytoken to be requested",
					EnvVars: []string{
						"MYTOKEN_PROFILE",
					},
					Destination: &mtCommand.profile,
					Placeholder: "PROFILE",
				},
			},
			getRestrFlags(&mtCommand.restrictionOpts)...,
		),
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
			Destination: &mtCommand.provider,
			Placeholder: "PROVIDER",
		},
		getCapabilityFlag(&mtCommand.CapabilitiesStr),
	)
	flags = append(flags, getRotationFlags(&mtCommand.RotationStr, &mtCommand.Rotation)...)
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
			Choice:      cli.NewStringChoice(api.ResponseTypeToken, cmdArgTokenTypeShort, cmdArgTokenTypeTransfer),
			Destination: &mtCommand.TokenType,
			Placeholder: "TYPE",
		},
		&cli.StringFlag{
			Name:        "out",
			Aliases:     []string{"o"},
			Usage:       "The mytoken will be printed to this output",
			Value:       os.Stdout.Name(),
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
	mt, err := obtainMT(context)
	if err != nil {
		return err
	}
	return cutils.WriteOutput(mtCommand.Out, mt)
}

func obtainMT(context *cli.Context) (string, error) {
	mytoken := config.Get().Mytoken()
	if mtCommand.TransferCode != "" {
		return mytoken.Mytoken.FromTransferCode(mtCommand.TransferCode)
	}
	req, err := mtCommand.Request(context)
	if err != nil {
		return "", err
	}
	prefix := config.Get().TokenNamePrefix
	if req.Name != "" && prefix != "" {
		req.Name = fmt.Sprintf("%s:%s", prefix, req.Name)
	}
	req.ApplicationName = fmt.Sprintf("mytoken client on %s", config.Get().Hostname)
	if ssh := mtCommand.SSH(); ssh != "" {
		req.GrantType = api.GrantTypeSSH
		mt, err := doSSHReturnOutput(ssh, api.SSHRequestMytoken, req)
		if mt != "" && mt[len(mt)-1] == '\n' {
			mt = mt[:len(mt)-1]
		}
		return mt, err
	}
	mtGrant := mtCommand.GetToken()
	if mtGrant != "" && !mtCommand.UseOIDCFlow {
		req.GrantType = api.GrantTypeMytoken
		mtRes, err := mytoken.Mytoken.APIFromRequest(
			api.MytokenFromMytokenRequest{
				GeneralMytokenRequest:        *req,
				Mytoken:                      mtGrant,
				FailOnRestrictionsNotTighter: true,
			},
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
	err = mtCommand.parseProviderOpt()
	if err != nil {
		return "", err
	}
	callbacks := mytokenlib.PollingCallbacks{
		Init: func(authorizationURL string) error {
			_, _ = fmt.Fprintln(
				os.Stderr,
				"Using any device please visit the following url to continue or use the qr code:",
			)
			_, _ = fmt.Fprintln(os.Stderr)
			_, _ = fmt.Fprintln(os.Stderr, authorizationURL)
			_, _ = fmt.Fprintln(os.Stderr)
			qr.FPrintQR(os.Stderr, authorizationURL)
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
	resp, err := mytoken.Mytoken.APIFromAuthorizationFlowReq(*req, callbacks)
	return resp.Mytoken, err
}
