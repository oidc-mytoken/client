package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oidc-mytoken/api/v0"
	"github.com/oidc-mytoken/utils/utils/jwtutils"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/tablewriter"
)

var infoOptions MTOptions

func init() {
	cmdFlags := getMTFlags()
	subCmdFlags := getMTFlags()
	cmd :=
		&cli.Command{
			Name:    "info",
			Aliases: []string{"tokeninfo"},
			Usage:   "Get information about a mytoken",
			Action:  info,
			Flags:   cmdFlags,
			Subcommands: []*cli.Command{
				{
					Name:   "history",
					Usage:  "List the event history for this token",
					Action: history,
					Flags:  subCmdFlags,
				},
				{
					Name: "subtokens",
					Aliases: []string{
						"token-tree",
						"tree",
					},
					Usage:  "List the tree of subtokens for this token",
					Action: subTree,
					Flags:  subCmdFlags,
				},
				{
					Name:   "introspect",
					Usage:  "Gives basic information about the token and its usages",
					Action: introspect,
					Flags:  subCmdFlags,
				},
				{
					Name:   "list-mytokens",
					Usage:  "List all mytokens",
					Action: listMytokens,
					Flags:  subCmdFlags,
				},
			},
		}
	app.Commands = append(app.Commands, cmd)
}

func prettyPrintJSONString(str string) error {
	var data interface{}
	if err := json.Unmarshal([]byte(str), &data); err != nil {
		return fmt.Errorf("%s", str)
	}
	return prettyPrintJSON(data)
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

func info(_ *cli.Context) error {
	mToken := infoOptions.MustGetToken()
	if !jwtutils.IsJWT(mToken) {
		return fmt.Errorf("The token is not a JWT.")
	}
	payload := strings.Split(mToken, ".")[1]
	decodedPayload, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(payload)
	if err != nil {
		return err
	}
	return prettyPrintJSON(decodedPayload)
}

func introspect(_ *cli.Context) error {
	if ssh := infoOptions.SSH(); ssh != "" {
		res, err := doSSHReturnOutput(ssh, api.SSHRequestTokenInfoIntrospect, nil)
		if err != nil {
			return err
		}
		return prettyPrintJSONString(res)
	}
	mytoken := config.Get().Mytoken
	mToken := infoOptions.MustGetToken()
	res, err := mytoken.Tokeninfo.Introspect(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

func history(_ *cli.Context) (err error) {
	var res api.TokeninfoHistoryResponse
	if ssh := infoOptions.SSH(); ssh != "" {
		var resStr string
		resStr, err = doSSHReturnOutput(ssh, api.SSHRequestTokenInfoHistory, nil)
		if err != nil {
			return
		}
		if err = json.Unmarshal([]byte(resStr), &res); err != nil {
			err = fmt.Errorf("%s", resStr)
			return
		}
	} else { // no ssh
		mytoken := config.Get().Mytoken
		mToken := infoOptions.MustGetToken()
		res, err = mytoken.Tokeninfo.APIHistory(mToken)
		if err != nil {
			return
		}
		if res.TokenUpdate != nil {
			updateMytoken(res.TokenUpdate.Mytoken)
		}
	}
	outputData := make([]tablewriter.TableWriter, len(res.EventHistory))
	for i, d := range res.EventHistory {
		outputData[i] = tableEventEntry(d)
	}
	tablewriter.PrintTableData(outputData)
	return nil
}

type tableEventEntry api.EventEntry

func (tableEventEntry) TableGetHeader() []string {
	return []string{
		"Event",
		"Comment",
		"Time",
		"IP",
		"User Agent",
	}
}
func (e tableEventEntry) TableGetRow() []string {
	const timeFmt = "2006-01-02 15:04:05"
	return []string{
		e.Event,
		e.Comment,
		time.Unix(e.Time, 0).Format(timeFmt),
		e.IP,
		e.UserAgent,
	}
}

func subTree(_ *cli.Context) (err error) {
	var res api.TokeninfoSubtokensResponse
	if ssh := infoOptions.SSH(); ssh != "" {
		var resStr string
		resStr, err = doSSHReturnOutput(ssh, api.SSHRequestTokenInfoSubtokens, nil)
		if err != nil {
			return
		}
		if err = json.Unmarshal([]byte(resStr), &res); err != nil {
			err = fmt.Errorf("%s", resStr)
			return
		}
	} else {
		mytoken := config.Get().Mytoken
		mToken := infoOptions.MustGetToken()
		res, err = mytoken.Tokeninfo.APISubtokens(mToken)
		if err != nil {
			return err
		}
		if res.TokenUpdate != nil {
			updateMytoken(res.TokenUpdate.Mytoken)
		}
	}
	return prettyPrintJSON(res.Tokens)
}

func listMytokens(_ *cli.Context) (err error) {
	var res api.TokeninfoListResponse
	if ssh := infoOptions.SSH(); ssh != "" {
		var resStr string
		resStr, err = doSSHReturnOutput(ssh, api.SSHRequestTokenInfoListMytokens, nil)
		if err != nil {
			return
		}
		if err = json.Unmarshal([]byte(resStr), &res); err != nil {
			err = fmt.Errorf("%s", resStr)
			return
		}
	} else {
		mytoken := config.Get().Mytoken
		mToken := infoOptions.MustGetToken()
		res, err = mytoken.Tokeninfo.APIListMytokens(mToken)
		if err != nil {
			return err
		}
		if res.TokenUpdate != nil {
			updateMytoken(res.TokenUpdate.Mytoken)
		}
	}
	return prettyPrintJSON(res.Tokens)
}
