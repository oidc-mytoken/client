package commands

import (
	"context"
	"os"

	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
	cutils "github.com/oidc-mytoken/client/internal/utils"
)

var atCommand = struct {
	MTOptions
	Scopes    []string
	Audiences []string
	Out       string
}{}

func init() {
	app.Commands = append(
		app.Commands, &cli.Command{
			Name: "AT",
			Aliases: []string{
				"at",
				"access-token",
			},
			Usage:  "Obtain an OIDC access token",
			Action: getAT,
			Flags: appendMTFlags(
				&cli.StringSliceFlag{
					Name:        "scope",
					Aliases:     []string{"s"},
					Usage:       "Request the passed scope.",
					DefaultText: "all scopes allowed for the used mytoken",
					Destination: &atCommand.Scopes,
				},
				&cli.StringSliceFlag{
					Name:        "aud",
					Aliases:     []string{"audience"},
					Usage:       "Request the passed audience.",
					Destination: &atCommand.Audiences,
				},
				&cli.StringFlag{
					Name:        "out",
					Aliases:     []string{"o"},
					Usage:       "The access token will be printed to this `FILE`",
					TakesFile:   true,
					Value:       os.Stdout.Name(),
					Destination: &atCommand.Out,
				},
			),
		},
	)
}

func getAT(ctx context.Context, cmd *cli.Command) error {
	atc := atCommand
	var comment string
	if cmd.Args().Len() > 0 {
		comment = cmd.Args().Get(0)
	}
	if ssh := atc.SSH(); ssh != "" {
		req := mytokenlib.NewAccessTokenRequest("", "", atc.Scopes, atc.Audiences, comment)
		return doSSH(ssh, api.SSHRequestAccessToken, req)
	}
	mToken := atc.MustGetToken()
	mytoken := config.Get().Mytoken()
	atRes, err := mytoken.AccessToken.APIGet(
		mToken, "", atc.Scopes, atc.Audiences, comment,
	)
	if err != nil {
		return err
	}
	if atRes.TokenUpdate != nil {
		updateMytoken(atRes.TokenUpdate.Mytoken)
	}
	return cutils.WriteOutput(atc.Out, atRes.AccessToken)
}
