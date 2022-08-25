package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

var revokeCommand = struct {
	PTOptions
	Recursive bool
}{}

func init() {
	app.Commands = append(
		app.Commands, &cli.Command{
			Name:   "revoke",
			Usage:  "Revokes a mytoken",
			Action: revoke,
			Flags: append(
				getPTFlags(),
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
	provider, mToken := revokeCommand.Check()
	err := mytoken.Revocation.Revoke(mToken, provider, revokeCommand.Recursive)
	if err == nil {
		fmt.Println("Token revoked")
	}
	return err
}
