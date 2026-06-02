package commands

import (
	"context"
	"fmt"

	"github.com/oidc-mytoken/api/v0"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
)

var emailOptions = struct {
	MTOptions
	EmailAddress    string
	PreferHTMLMail  bool
	PreferPlainMail bool
}{}

func initEmail(parent *cli.Command) {
	cmd := &cli.Command{
		Name:  "email",
		Usage: "View and update your email preferences",
		Commands: []*cli.Command{
			{
				Name:   "get",
				Usage:  "Get your email information",
				Action: getEmail,
				Flags:  getMTFlags(),
			},
			{
				Name:   "update",
				Usage:  "Update your email preferences",
				Action: updateEmail,
				Flags: append(
					getMTFlags(),
					&cli.StringFlag{
						Name:        "email",
						Usage:       "New email address",
						Destination: &emailOptions.EmailAddress,
					},
					&cli.BoolFlag{
						Name:        "html",
						Usage:       "Prefer HTML mails over plain text",
						Destination: &emailOptions.PreferHTMLMail,
					},
					&cli.BoolFlag{
						Name:        "plain",
						Usage:       "Prefer plain text mails over HTML",
						Destination: &emailOptions.PreferPlainMail,
					},
				),
			},
		},
	}
	parent.Commands = append(parent.Commands, cmd)
}

func getEmail(_ context.Context, _ *cli.Command) error {
	if ssh := emailOptions.SSH(); ssh != "" {
		res, err := doSSHParseJSON[api.MailSettingsInfoResponse](ssh, api.SSHRequestEmailGet, nil)
		if err != nil {
			return err
		}
		fmt.Println("Email Information:")
		fmt.Printf("  Email Address:    %s\n", res.EmailAddress)
		fmt.Printf("  Verified:         %v\n", res.EmailVerified)
		fmt.Printf("  Prefer HTML Mail: %v\n", res.PreferHTMLMail)
		return nil
	}
	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.UserSettings.Email.APIGet(mytoken)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Println("Email Information:")
	fmt.Printf("  Email Address:    %s\n", res.EmailAddress)
	fmt.Printf("  Verified:         %v\n", res.EmailVerified)
	fmt.Printf("  Prefer HTML Mail: %v\n", res.PreferHTMLMail)
	return nil
}

func updateEmail(_ context.Context, _ *cli.Command) error {
	if emailOptions.EmailAddress == "" && !emailOptions.PreferHTMLMail && !emailOptions.PreferPlainMail {
		return fmt.Errorf("at least one of --email, --html, or --plain must be provided")
	}

	var preferHTML *bool
	if emailOptions.PreferHTMLMail {
		val := true
		preferHTML = &val
	} else if emailOptions.PreferPlainMail {
		val := false
		preferHTML = &val
	}

	if ssh := emailOptions.SSH(); ssh != "" {
		req := api.UpdateMailSettingsRequest{
			EmailAddress:   emailOptions.EmailAddress,
			PreferHTMLMail: preferHTML,
		}
		return doSSH(ssh, api.SSHRequestEmailSet, &req)
	}

	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()
	res, err := mtServer.UserSettings.Email.APIUpdate(mytoken, emailOptions.EmailAddress, preferHTML)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Println("Email preferences updated successfully")
	return nil
}
