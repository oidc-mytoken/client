package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oidc-mytoken/server/pkg/model"
	"github.com/oidc-mytoken/server/shared/supertoken/capabilities"
	"github.com/oidc-mytoken/server/shared/supertoken/restrictions"
	"github.com/oidc-mytoken/server/shared/utils"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/cryptutils"
	"github.com/oidc-mytoken/client/internal/utils/duration"
)

func init() {
	options.ST.CommonSTOptions = &CommonSTOptions{}
	options.ST.Store.CommonSTOptions = options.ST.CommonSTOptions
	st, _ := parser.AddCommand("ST", "Obtain super token", "Obtain a new mytoken super token", &options.ST)
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

type stCommand struct {
	Store stStoreCommand `command:"store" description:"Store the obtained super token encrypted instead of returning it. This way the super token can be easily used with mytoken."`

	*CommonSTOptions

	TokenType string `long:"token-type" choice:"short" choice:"transfer" choice:"token" default:"token" description:"The type of the returned token. Can only be used if token is not stored."`
}

type CommonSTOptions struct {
	ptOptions
	TransferCode string `long:"TC" description:"Use the passed transfer code to exchange it into a super token"`
	OIDCFlow     string `long:"oidc" choice:"auth" choice:"device" choice:"default" optional:"true" optional-value:"default" description:"Use the passed OpenID Connect flow to create a super token"`

	Capabilities         []string `long:"capability" default:"default" description:"Request the passed capabilities. Can be used multiple times"`
	SubtokenCapabilities []string `long:"subtoken-capability" description:"Request the passed subtoken capabilities. Can be used multiple times"`
	Restrictions         string   `long:"restrictions" description:"The restrictions that restrict the requested super token. Can be a json object or array or '@<filepath>' where <filepath> is the path to a json file.'"`

	RestrictScopes        []string `long:"scope" short:"s" description:"Restrict the supertoken so that it can only be used to request ATs with these scopes. Can be used multiple times. Overwritten by --restriction."`
	RestrictAudiences     []string `long:"aud" description:"Restrict the supertoken so that it can only be used to request ATs with these audiences. Can be used multiple times. Overwritten by --restriction."`
	RestrictExp           string   `long:"exp" description:"Restrict the supertoken so that it cannot be used after this time. The time given can be an absolute time given as a unix timestamp, a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'."`
	RestrictNbf           string   `long:"nbf" description:"Restrict the supertoken so that it cannot be used before this time. The time given can be an absolute time given as a unix timestamp, a relative time string starting with '+' or an absolute time string '2006-01-02 15:04'."`
	RestrictIP            []string `long:"ip" description:"Restrict the supertoken so that it can only be used from these ips. Can be a network address block or a single ip. Can be given multiple times."`
	RestrictGeoIPAllow    []string `long:"geo-ip-allow" description:"Restrict the supertoken so that it can be only used from these countries. Must be a short country code, e.g. 'us'. Can be given multiple times."`
	RestrictGeoIPDisallow []string `long:"geo-ip-disallow" description:"Restrict the supertoken so that it cannot be used from these countries. Must be a short country code, e.g. 'us'. Can be given multiple times."`
	RestrictUsagesOther   *int64   `long:"usages-other" description:"Restrict how often the supertoken can be used for actions other than requesting an access token."`
	RestrictUsagesAT      *int64   `long:"usages-at" description:"Restrict how often the supertoken can be used for requesting an access token."`
}

type stStoreCommand struct {
	*CommonSTOptions
	PositionalArgs struct {
		StoreName string `positional-arg-name:"NAME" description:"Store the obtained super token under NAME. It can be used later by referencing NAME."`
	} `positional-args:"true" required:"true"`
	GPGKey   string `short:"k" long:"gpg-key" value-name:"KEY" description:"Use KEY for encryption instead of the default key"`
	Password bool   `long:"password" description:"Use a password for encrypting the token instead of a gpg key."`
}

// Execute implements the flags.Commander interface
func (stc *stCommand) Execute(args []string) error {
	if len(stc.Capabilities) > 0 && stc.Capabilities[0] == "default" {
		stc.Capabilities = config.Get().DefaultTokenCapabilities.Returned
	}
	st, err := obtainST(stc.CommonSTOptions, "", model.NewResponseType(stc.TokenType))
	if err != nil {
		return err
	}
	fmt.Println(st)
	return nil
}

func obtainST(args *CommonSTOptions, name string, responseType model.ResponseType) (string, error) {
	mytoken := config.Get().Mytoken
	if args.TransferCode != "" {
		return mytoken.GetSuperTokenByTransferCode(args.TransferCode)
	}
	provider, err := args.ptOptions.checkProvider(args.Name)
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
			return mytoken.GetSuperTokenByAuthorizationFlow(provider.Issuer, r, c, sc, responseType, tokenName,
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
	stGrant, err := args.ptOptions.checkToken(provider.Issuer)
	if err != nil {
		return "", err
	}
	return mytoken.GetSuperTokenBySuperToken(stGrant, provider.Issuer, r, c, sc, responseType, tokenName)
}

// Execute implements the flags.Commander interface
func (sstc *stStoreCommand) Execute(args []string) error {
	if len(sstc.Capabilities) > 0 && sstc.Capabilities[0] == "default" {
		sstc.Capabilities = config.Get().DefaultTokenCapabilities.Stored
	}
	provider, err := sstc.CommonSTOptions.ptOptions.checkProvider(sstc.Name)
	if err != nil {
		return err
	}
	st, err := obtainST(sstc.CommonSTOptions, sstc.PositionalArgs.StoreName, model.ResponseTypeToken)
	if err != nil {
		return err
	}
	gpgKey := sstc.GPGKey
	if sstc.Password {
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
	if err = saveEncryptedToken(encryptedToken, provider.Issuer, sstc.PositionalArgs.StoreName, gpgKey); err != nil {
		return err
	}
	fmt.Printf("Saved super token '%s'\n", sstc.PositionalArgs.StoreName)
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

func parseTime(t string) (int64, error) {
	if t == "" {
		return 0, nil
	}
	i, err := strconv.ParseInt(t, 10, 64)
	if err == nil {
		if t[0] == '+' {
			return utils.GetUnixTimeIn(i), nil
		}
		return i, nil
	}
	if t[0] == '+' {
		d, err := duration.ParseDuration(t[1:])
		return time.Now().Add(d).Unix(), err
	}
	tt, err := time.ParseInLocation("2006-01-02 15:04", t, time.Local)
	return tt.Unix(), err
}
