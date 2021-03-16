package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oidc-mytoken/server/shared/utils"

	"github.com/oidc-mytoken/client/internal/config"
)

// infoCommand is a type for holding and handling the info command
type infoCommand struct {
	*PTOptions
	EventHistory historyCommand      `command:"history" description:"List the event history for this token"`
	SubTree      subTreeCommand      `command:"subtokens" description:"List the tree of subtokens for this token"`
	Introspect   introspectCommand   `command:"introspect" description:"Gives basic information about this token and its usages"`
	TokenList    listMytokensCommand `command:"list-mytokens" description:"List all mytokens"`
}

// introspectCommand is a type for holding and handling the info command
type introspectCommand struct {
	*PTOptions
}

// historyCommand is a type for holding and handling the info command
type historyCommand struct {
	*PTOptions
}

// subTreeCommand is a type for holding and handling the info command
type subTreeCommand struct {
	*PTOptions
}

// listMytokensCommand is a type for holding and handling the info command
type listMytokensCommand struct {
	*PTOptions
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
	info := infoBuffer.String()
	fmt.Println(info)
	return nil
}

// Execute implements the flags.Commander interface
func (ic *infoCommand) Execute(args []string) error {
	_, mToken := ic.Check()
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

// Execute implements the flags.Commander interface
func (ic *introspectCommand) Execute(args []string) error {
	mytoken := config.Get().Mytoken
	_, mToken := ic.Check()
	res, err := mytoken.TokeninfoIntrospect(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

// Execute implements the flags.Commander interface
func (hc *historyCommand) Execute(args []string) error {
	mytoken := config.Get().Mytoken
	_, mToken := hc.Check()
	res, err := mytoken.TokeninfoHistory(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

// Execute implements the flags.Commander interface
func (sc *subTreeCommand) Execute(args []string) error {
	mytoken := config.Get().Mytoken
	_, mToken := sc.Check()
	res, err := mytoken.TokeninfoSubtokens(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

// Execute implements the flags.Commander interface
func (lc *listMytokensCommand) Execute(args []string) error {
	mytoken := config.Get().Mytoken
	_, mToken := lc.Check()
	res, err := mytoken.TokeninfoListMytokens(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}
