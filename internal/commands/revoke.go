package commands

import (
	"fmt"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/zachmann/cli/v2"
)

var revokeCommand = struct {
	*PTOptions
	Recursive bool
}{}

func init() {
	ptFlags, opts := getPTFlags()
	revokeCommand.PTOptions = opts
	app.Commands = append(app.Commands, &cli.Command{
		Name:   "revoke",
		Usage:  "Revokes a mytoken",
		Action: revoke,
		Flags: append(ptFlags,
			&cli.BoolFlag{
				Name:             "recursive",
				Aliases:          []string{"r"},
				Usage:            "If set, also all subtokens are revoked",
				Destination:      &revokeCommand.Recursive,
				HideDefaultValue: true,
			},
		),
	})
}

func revoke(context *cli.Context) error {
	mytoken := config.Get().Mytoken
	provider, mToken := revokeCommand.Check()
	err := mytoken.Revoke(mToken, provider.Issuer, revokeCommand.Recursive)
	if err != nil {
		return err
	}
	fmt.Println("Token revoked")
	return nil
}
