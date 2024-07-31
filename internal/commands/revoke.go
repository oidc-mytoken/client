package commands

import (
	"fmt"

	"github.com/oidc-mytoken/api/v0"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

var revokeCommand = struct {
	MTOptions
	Recursive bool
	MOMID     string
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
				&cli.StringFlag{
					Name: "mom-id",
					Aliases: []string{
						"MOM-ID",
						"mom",
						"MOM",
					},
					Usage: fmt.Sprintf(
						"If set, "+
							"the mytoken with the passed mom id is revoked instead of the actual token.	"+
							"This requires that the token linked to the mom id is either a child of the actual mytoken or"+
							" the actual mytoken has the %s capability.", api.CapabilityRevokeAnyToken,
					),
					EnvVars:     []string{"MOM_ID"},
					Destination: &revokeCommand.MOMID,
					Placeholder: "MOM_ID",
				},
			),
		},
	)
}

func revoke(_ *cli.Context) error {
	mToken := revokeCommand.MustGetToken()
	mytoken := config.Get().Mytoken()
	var err error
	if revokeCommand.MOMID != "" {
		err = mytoken.Revocation.RevokeID(revokeCommand.MOMID, mToken, "", revokeCommand.Recursive)
	} else {
		err = mytoken.Revocation.Revoke(mToken, "", revokeCommand.Recursive)
	}
	if err == nil {
		fmt.Println("Token revoked")
	}
	return err
}
