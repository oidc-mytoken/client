package commands

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oidc-mytoken/api/v0"
	"github.com/oidc-mytoken/utils/utils/jwtutils"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/color"
	"github.com/oidc-mytoken/client/internal/utils/tablewriter"
)

var infoOptions MTOptions

var infoNotificationsOptions = struct {
	MTOptions
	MOMIDs []string
}{}

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
			Commands: []*cli.Command{
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
					Name:    "list-mytokens",
					Aliases: []string{"list"},
					Usage:   "List all mytokens",
					Action:  listMytokens,
					Flags: append(
						subCmdFlags,
						&cli.BoolFlag{
							Name:  "include-mom-id",
							Usage: "Include the MOM-ID column in the output",
						},
					),
				},
				{
					Name:   "notifications",
					Usage:  "Get notifications and calendars for this token",
					Action: infoNotifications,
					Flags: append(
						subCmdFlags,
						&cli.StringSliceFlag{
							Name:        "mom-id",
							Usage:       "Request notifications for specific mom_ids (special values: 'this', 'children')",
							Destination: &infoNotificationsOptions.MOMIDs,
						},
					),
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

func info(_ context.Context, _ *cli.Command) error {
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

func introspect(_ context.Context, _ *cli.Command) error {
	if ssh := infoOptions.SSH(); ssh != "" {
		res, err := doSSHReturnOutput(ssh, api.SSHRequestTokenInfoIntrospect, nil)
		if err != nil {
			return err
		}
		return prettyPrintJSONString(res)
	}
	mToken := infoOptions.MustGetToken()
	mytoken := config.Get().Mytoken()
	res, err := mytoken.Tokeninfo.Introspect(mToken)
	if err != nil {
		return err
	}
	return prettyPrintJSON(res)
}

func history(_ context.Context, _ *cli.Command) (err error) {
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
		mToken := infoOptions.MustGetToken()
		mytoken := config.Get().Mytoken()
		res, err = mytoken.Tokeninfo.APIHistory(mToken)
		if err != nil {
			return
		}
		if res.TokenUpdate != nil {
			updateMytoken(res.TokenUpdate.Mytoken)
		}
	}
	outputData := make([]tablewriter.TableWriter, len(res.EventHistory.Events))
	for i, d := range res.EventHistory.Events {
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
		string(e.Event),
		e.Comment,
		time.Unix(e.Time, 0).Format(timeFmt),
		e.IP,
		e.UserAgent,
	}
}

func subTree(_ context.Context, _ *cli.Command) (err error) {
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
		mToken := infoOptions.MustGetToken()
		mytoken := config.Get().Mytoken()
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

func listMytokens(_ context.Context, cmd *cli.Command) (err error) {
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
		mToken := infoOptions.MustGetToken()
		mytoken := config.Get().Mytoken()
		res, err = mytoken.Tokeninfo.APIListMytokens(mToken)
		if err != nil {
			return err
		}
		if res.TokenUpdate != nil {
			updateMytoken(res.TokenUpdate.Mytoken)
		}
	}
	includeMOMID := cmd.Bool("include-mom-id")
	outputData := flattenMytokenEntryTree(res.Tokens, includeMOMID)
	tablewriter.PrintTableData(outputData)
	return nil
}

func flattenMytokenEntryTree(tree []api.MytokenEntryTree, includeMOMID bool) []tablewriter.TableWriter {
	var result []tablewriter.TableWriter
	for _, entry := range tree {
		result = append(
			result, tableMytokenEntry{
				entry:        entry.Token,
				depth:        0,
				includeMOMID: includeMOMID,
			},
		)
		result = append(result, flattenMytokenEntryTreeRecursive(entry.Children, 1, includeMOMID)...)
	}
	return result
}

func flattenMytokenEntryTreeRecursive(
	tree []api.MytokenEntryTree, depth int, includeMOMID bool,
) []tablewriter.TableWriter {
	var result []tablewriter.TableWriter
	for _, entry := range tree {
		result = append(
			result, tableMytokenEntry{
				entry:        entry.Token,
				depth:        depth,
				includeMOMID: includeMOMID,
			},
		)
		result = append(result, flattenMytokenEntryTreeRecursive(entry.Children, depth+1, includeMOMID)...)
	}
	return result
}

type tableMytokenEntry struct {
	entry        api.MytokenEntry
	depth        int
	includeMOMID bool
}

func (e tableMytokenEntry) TableGetHeader() []string {
	if e.includeMOMID {
		return []string{
			"MOM-ID",
			"Name",
			"Created",
			"Expires",
			"Tags",
			"IP",
		}
	}
	return []string{
		"Name",
		"Created",
		"Expires",
		"Tags",
		"IP",
	}
}

func (e tableMytokenEntry) TableGetRow() []string {
	const timeFmt = "2006-01-02 15:04:05"
	now := time.Now().Unix()

	created := time.Unix(e.entry.CreatedAt, 0).Format(timeFmt)
	expires := ""
	expired := false
	if e.entry.ExpiresAt > 0 {
		expires = time.Unix(e.entry.ExpiresAt, 0).Format(timeFmt)
		expired = e.entry.ExpiresAt < now
	} else {
		expires = color.Italic("does not expire")
	}

	tags := ""
	if len(e.entry.Tags) > 0 {
		tagStrs := make([]string, len(e.entry.Tags))
		for i, t := range e.entry.Tags {
			tagStrs[i] = color.ColorizeText(string(t.Tag), t.Color)
		}
		tags = strings.Join(tagStrs, ", ")
	}

	name := e.entry.Name
	if name == "" {
		name = color.Italic("unnamed token")
	}
	if e.depth > 0 {
		name = strings.Repeat("  ", e.depth) + "└─ " + name
	}

	if expired {
		name = color.Gray(name)
		created = color.Gray(created)
		expires = color.Gray(expires)
		tags = color.Gray(tags)
	}

	if e.includeMOMID {
		return []string{
			e.entry.MOMID,
			name,
			created,
			expires,
			tags,
			e.entry.IP,
		}
	}
	return []string{
		name,
		created,
		expires,
		tags,
		e.entry.IP,
	}
}

func infoNotifications(_ context.Context, _ *cli.Command) (err error) {
	mToken := infoNotificationsOptions.MustGetToken()
	mytoken := config.Get().Mytoken()

	var momIDs []string
	if len(infoNotificationsOptions.MOMIDs) > 0 {
		momIDs = infoNotificationsOptions.MOMIDs
	}

	res, err := mytoken.Tokeninfo.APINotifications(mToken, momIDs)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	if len(res.Notifications) > 0 {
		fmt.Println("Notifications:")
		outputData := make([]tablewriter.TableWriter, len(res.Notifications))
		for i, n := range res.Notifications {
			outputData[i] = tableNotificationInfo(n)
		}
		tablewriter.PrintTableData(outputData)
		fmt.Println()
	}

	if len(res.Calendars) > 0 {
		fmt.Println("Calendars:")
		outputData := make([]tablewriter.TableWriter, len(res.Calendars))
		for i, c := range res.Calendars {
			outputData[i] = tableCalendarInfo(c)
		}
		tablewriter.PrintTableData(outputData)
		fmt.Println()
	}

	if len(res.Notifications) == 0 && len(res.Calendars) == 0 {
		fmt.Println("No notifications or calendars found.")
	}

	return nil
}

type tableNotificationInfo api.NotificationInfo

func (tableNotificationInfo) TableGetHeader() []string {
	return []string{
		"Type",
		"Management Code",
		"Classes",
		"User Wide",
		"Tags",
	}
}

func (n tableNotificationInfo) TableGetRow() []string {
	classes := make([]string, len(n.Classes))
	for i, c := range n.Classes {
		classes[i] = c.Name
	}

	tags := ""
	if len(n.Tags) > 0 {
		tagStrs := make([]string, len(n.Tags))
		for i, t := range n.Tags {
			tagStrs[i] = color.ColorizeText(string(t.Tag), t.Color)
		}
		tags = strings.Join(tagStrs, ", ")
	}

	return []string{
		n.Type,
		n.ManagementCode,
		strings.Join(classes, ", "),
		fmt.Sprintf("%v", n.UserWide),
		tags,
	}
}

type tableCalendarInfo api.CalendarInfo

func (tableCalendarInfo) TableGetHeader() []string {
	return []string{
		"Description",
		"Tags",
	}
}

func (c tableCalendarInfo) TableGetRow() []string {
	tags := ""
	if len(c.Tags) > 0 {
		tagStrs := make([]string, len(c.Tags))
		for i, t := range c.Tags {
			tagStrs[i] = color.ColorizeText(string(t.Tag), t.Color)
		}
		tags = strings.Join(tagStrs, ", ")
	}

	return []string{
		c.Description,
		tags,
	}
}
