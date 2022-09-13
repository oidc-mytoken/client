package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

var revokeCommand = struct {
	MTOptions
	Recursive bool
}{}

func init() {
	app.Commands = append(
		app.Commands, &cli.Command{
			Name:   "revoke",
			Usage:  "Revokes a mytoken",
			Action: revoke,
			Flags: appendMTFlags(
				&cli.BoolFlag{
					Name:             "recursive",
					Aliases:          []string{"r"},
					Usage:            "If set, also all subtokens are revoked",
					Destination:      &revokeCommand.Recursive,
					HideDefaultValue: true,
				},
			),
		},
	)
}

func revoke(_ *cli.Context) error {
	mytoken := config.Get().Mytoken
	mToken := revokeCommand.MustGetToken()
	err := mytoken.Revocation.Revoke(mToken, "", revokeCommand.Recursive)
	if err == nil {
		fmt.Println("Token revoked")
	}
	return err
}
