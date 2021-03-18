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
	"github.com/oidc-mytoken/server/pkg/model"
	"github.com/oidc-mytoken/server/shared/mytoken/capabilities"
	"github.com/oidc-mytoken/server/shared/mytoken/restrictions"
	"github.com/oidc-mytoken/server/shared/utils/unixtime"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/cryptutils"
	"github.com/oidc-mytoken/client/internal/utils/duration"
)

func mt_init() {
	options.MT.CommonMTOptions = &CommonMTOptions{}
	options.MT.Store.CommonMTOptions = options.MT.CommonMTOptions
	st, _ := parser.AddCommand("MT", "Obtain a mytoken", "Obtain a new mytoken mytoken", &options.MT)
	st.SubcommandsOptional = true
	for _, o := range st.Options() {
		if o.LongName == "capability" {
			o.Choices = capabilities.AllCapabilities.Strings()
		}
		if o.LongName == "subtoken-capability" {
			o.Choices = capabilities.AllCapabilities.Strings()
		}
	}
}

type mtCommand struct {
	Store mtStoreCommand `command:"store" description:"Store the obtained mytoken encrypted instead of returning it. This way the mytoken can be easily used with mytoken."`

	*CommonMTOptions

	TokenType string `long:"token-type" choice:"short" choice:"transfer" choice:"token" default:"token" description:"The type of the returned token. Can only be used if token is not stored."`
	Out       string `long:"out" short:"o" default:"/dev/stdout" description:"The mytoken will be printed to this output."`
}

type CommonMTOptions struct {
	PTOptions
	TransferCode string `long:"TC" description:"Use the passed transfer code to exchange it into a mytoken"`
	OIDCFlow     string `long:"oidc" choice:"auth" choice:"device" choice:"default" optional:"true" optional-value:"default" description:"Use the passed OpenID Connect flow to create a mytoken"`

	Capabilities         []string `long:"capability" default:"default" description:"Request the passed capabilities. Can be used multiple times"`
	SubtokenCapabilities []string `long:"subtoken-capability" description:"Request the passed subtoken capabilities. Can be used multiple times"`
	Restrictions         string   `long:"restrictions" description:"The restrictions that restrict the requested mytoken. Can be a json object or array or '@<filepath>' where <filepath> is the path to a json file.'"`

	RestrictScopes        []string `long:"scope" short:"s" description:"Restrict the mytoken so that it can only be used to request ATs with these scopes. Can be used multiple times. Overwritten by --restriction."`
	RestrictAudiences     []string `long:"aud" description:"Restrict the mytoken so that it can only be used to request ATs with these audiences. Can be used multiple times. Overwritten by --restriction."`
	RestrictExp           string   `long:"exp" description:"Restrict the mytoken so that it cannot be used after this time. The time given can be an absolute time given as a unix timestamp, a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'."`
	RestrictNbf           string   `long:"nbf" description:"Restrict the mytoken so that it cannot be used before this time. The time given can be an absolute time given as a unix timestamp, a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'."`
	RestrictIP            []string `long:"ip" description:"Restrict the mytoken so that it can only be used from these ips. Can be a network address block or a single ip. Can be given multiple times."`
	RestrictGeoIPAllow    []string `long:"geo-ip-allow" description:"Restrict the mytoken so that it can be only used from these countries. Must be a short country code, e.g. 'us'. Can be given multiple times."`
	RestrictGeoIPDisallow []string `long:"geo-ip-disallow" description:"Restrict the mytoken so that it cannot be used from these countries. Must be a short country code, e.g. 'us'. Can be given multiple times."`
	RestrictUsagesOther   *int64   `long:"usages-other" description:"Restrict how often the mytoken can be used for actions other than requesting an access token."`
	RestrictUsagesAT      *int64   `long:"usages-at" description:"Restrict how often the mytoken can be used for requesting an access token."`
}

type mtStoreCommand struct {
	*CommonMTOptions
	PositionalArgs struct {
		StoreName string `positional-arg-name:"NAME" description:"Store the obtained mytoken under NAME. It can be used later by referencing NAME."`
	} `positional-args:"true" required:"true"`
	GPGKey   string `short:"k" long:"gpg-key" value-name:"KEY" description:"Use KEY for encryption instead of the default key"`
	Password bool   `long:"password" description:"Use a password for encrypting the token instead of a gpg key."`
}

// Execute implements the flags.Commander interface
func (mtc *mtCommand) Execute(args []string) error {
	if len(mtc.Capabilities) > 0 && mtc.Capabilities[0] == "default" {
		mtc.Capabilities = config.Get().DefaultTokenCapabilities.Returned
	}

	st, err := obtainMT(mtc.CommonMTOptions, "", model.NewResponseType(mtc.TokenType))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(mtc.Out, append([]byte(st), '\n'), 0600)
}

func obtainMT(args *CommonMTOptions, name string, responseType model.ResponseType) (string, error) {
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
	var r restrictions.Restrictions
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
		r = restrictions.Restrictions{
			restrictions.Restriction{
				NotBefore:     nbf,
				ExpiresAt:     exp,
				Scope:         strings.Join(args.RestrictScopes, " "),
				Audiences:     args.RestrictAudiences,
				IPs:           args.RestrictIP,
				GeoIPAllow:    args.RestrictGeoIPAllow,
				GeoIPDisallow: args.RestrictGeoIPDisallow,
				UsagesAT:      args.RestrictUsagesAT,
				UsagesOther:   args.RestrictUsagesOther,
			},
		}
	}
	c := capabilities.NewCapabilities(args.Capabilities)
	sc := capabilities.NewCapabilities(args.SubtokenCapabilities)
	if args.OIDCFlow != "" {
		if args.OIDCFlow == "default" {
			args.OIDCFlow = config.Get().DefaultOIDCFlow
		}
		switch args.OIDCFlow {
		case "auth":
			return mytoken.GetMytokenByAuthorizationFlow(provider.Issuer, r, c, sc, responseType, tokenName,
				func(authorizationURL string) error {
					fmt.Fprintln(os.Stderr, "Using any device please visit the following url to continue:")
					fmt.Fprintln(os.Stderr)
					fmt.Fprintln(os.Stderr, authorizationURL)
					fmt.Fprintln(os.Stderr)
					return nil
				},
				func(interval int64, iteration int) {
					if iteration == 0 {
						fmt.Fprint(os.Stderr, "Starting polling ... ")
						return
					}
					if int64(iteration)%(30/interval) == 0 { // every 30s
						fmt.Fprint(os.Stderr, ".")
					}
				},
				func() {
					fmt.Fprintln(os.Stderr)
					fmt.Fprintln(os.Stderr, "success")
				},
			)
		case "device":
			return "", fmt.Errorf("Not yet implemented")
		default:
			return "", fmt.Errorf("Unknown oidc flow. Implementation error.")
		}
	}
	stGrant, err := args.PTOptions.checkToken(provider.Issuer)
	if err != nil {
		return "", err
	}
	return mytoken.GetMytokenByMytoken(stGrant, provider.Issuer, r, c, sc, responseType, tokenName)
}

// Execute implements the flags.Commander interface
func (smtc *mtStoreCommand) Execute(args []string) error {
	if len(smtc.Capabilities) > 0 && smtc.Capabilities[0] == "default" {
		smtc.Capabilities = config.Get().DefaultTokenCapabilities.Stored
	}
	provider, err := smtc.CommonMTOptions.PTOptions.checkProvider(smtc.Name)
	if err != nil {
		return err
	}
	if config.Get().TokensFileContent.Has(smtc.PositionalArgs.StoreName, provider.Issuer) {
		pStr := provider.Name
		if pStr == "" {
			pStr = provider.Issuer
		}
		if !prompter.YN(fmt.Sprintf("A token with the name '%s' is already stored for the provider '%s'. Do you want to overwrite it?", smtc.PositionalArgs.StoreName, pStr), false) {
			os.Exit(1)
		}
	}
	st, err := obtainMT(smtc.CommonMTOptions, smtc.PositionalArgs.StoreName, model.ResponseTypeToken)
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
	if err = saveEncryptedToken(encryptedToken, provider.Issuer, smtc.PositionalArgs.StoreName, gpgKey); err != nil {
		return err
	}
	fmt.Printf("Saved mytoken '%s'\n", smtc.PositionalArgs.StoreName)
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
	restrictions.Restriction
	NotBefore string `json:"nbf,omitempty"`
	ExpiresAt string `json:"exp,omitempty"`
}

type restriction restrictions.Restriction

func parseRestrictionOption(arg string) (restrictions.Restrictions, error) {
	if arg == "" {
		return nil, nil
	}
	if arg[0] == '@' {
		data, err := ioutil.ReadFile(arg[1:])
		if err != nil {
			return nil, err
		}
		return parseRestrictions(string(data))
	}
	return parseRestrictions(arg)
}

func parseRestrictions(str string) (restrictions.Restrictions, error) {
	str = strings.TrimSpace(str)
	switch str[0] {
	case '[': // multiple restrictions
		var rs []restriction
		err := json.Unmarshal([]byte(str), &rs)
		r := restrictions.Restrictions{}
		for _, rr := range rs {
			r = append(r, restrictions.Restriction(rr))
		}
		return r, err
	case '{': // single restriction
		var r restriction
		err := json.Unmarshal([]byte(str), &r)
		return restrictions.Restrictions{restrictions.Restriction(r)}, err
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

func parseTime(t string) (unixtime.UnixTime, error) {
	if t == "" {
		return 0, nil
	}
	i, err := strconv.ParseInt(t, 10, 64)
	if err == nil {
		if t[0] == '+' {
			return unixtime.InSeconds(i), nil
		}
		return unixtime.UnixTime(i), nil
	}
	if t[0] == '+' {
		d, err := duration.ParseDuration(t[1:])
		return unixtime.New(time.Now().Add(d)), err
	}
	tt, err := time.ParseInLocation("2006-01-02 15:04", t, time.Local)
	return unixtime.New(tt), err
}
