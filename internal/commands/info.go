package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

var infoOptions *PTOptions

func init() {
	var flags []cli.Flag
	flags, infoOptions = getPTFlags()
	cmd :=
		&cli.Command{
			Name:   "info",
			Usage:  "Get information about a mytoken",
			Action: info,
			Flags:  flags,
			Subcommands: []*cli.Command{
				{
					Name:   "history",
					Usage:  "List the event history for this token",
					Action: history,
					Flags:  flags,
				},
				{
					Name:    "subtokens",
					Aliases: []string{"token-tree", "tree"},
					Usage:   "List the tree of subtokens for this token",
					Action:  subTree,
					Flags:   flags,
				},
				{
					Name:   "introspect",
					Usage:  "Gives basic information about the token and its usages",
					Action: introspect,
					Flags:  flags,
				},
				{
					Name:   "list-mytokens",
					Usage:  "List all mytokens",
					Action: listMytokens,
					Flags:  flags,
				},
			},
		}
	app.Commands = append(app.Commands, cmd)
}

func prettyPrintJSON(obj interface{}) error {
	var data []byte
	switch v := obj.(type) {
	case []byte:
		data = v
	default:
		tmp, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("Internal error: %s", err)
		}
		data = tmp
	}
	var infoBuffer bytes.Buffer
	if err := json.Indent(&infoBuffer, data, "", "  "); err != nil {
		return err
	}
	fmt.Println(infoBuffer.String())
	return nil
}

func info(ctx *cli.Context) error {
	_, mToken := infoOptions.Check()
	if !utils.IsJWT(mToken) {
		return fmt.Errorf("The token is not a JWT.")
	}
	payload := strings.Split(mToken, ".")[1]
	decodedPayload, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(payload)
	if err != nil {
		return err
	}
	return prettyPrintJSON(decodedPayload)
}

func introspect(ctx *cli.Context) error {
	mytoken := config.Get().Mytoken
	_, mToken := infoOptions.Check()
	res, err := mytoken.TokeninfoIntrospect(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

func history(ctx *cli.Context) error {
	mytoken := config.Get().Mytoken
	_, mToken := infoOptions.Check()
	res, err := mytoken.TokeninfoHistory(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

func subTree(ctx *cli.Context) error {
	mytoken := config.Get().Mytoken
	_, mToken := infoOptions.Check()
	res, err := mytoken.TokeninfoSubtokens(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

func listMytokens(ctx *cli.Context) error {
	mytoken := config.Get().Mytoken
	_, mToken := infoOptions.Check()
	res, err := mytoken.TokeninfoListMytokens(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}
