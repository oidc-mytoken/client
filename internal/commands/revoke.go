package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
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

func revoke(_ *cli.Context) error {
	mytoken := config.Get().Mytoken
	provider, mToken := revokeCommand.Check()
	err := mytoken.Revoke(mToken, provider.Issuer, revokeCommand.Recursive)
	if err != nil {
		return err
	}
	fmt.Println("Token revoked")
	if revokeCommand.Name == "" || provider == nil {
		return nil
	}
	config.Get().TokensFileContent.Remove(revokeCommand.Name, provider.Issuer)
	if err = config.Get().TokensFileContent.Save(); err != nil {
		return err
	}
	fmt.Println("Token deleted")
	return nil
}
