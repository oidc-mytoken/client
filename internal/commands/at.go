package commands

import (
	"io/ioutil"

	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

var atCommand = struct {
	*PTOptions
	Scopes    cli.StringSlice
	Audiences cli.StringSlice
	Out       string
}{}

func init() {
	ptFlags, opts := getPTFlags()
	atCommand.PTOptions = opts
	app.Commands = append(app.Commands, &cli.Command{
		Name:    "AT",
		Aliases: []string{"at", "access-token"},
		Usage:   "Obtain an OIDC access token",
		Action:  getAT,
		Flags: append(ptFlags,
			&cli.StringSliceFlag{
				Name:        "scope",
				Aliases:     []string{"s"},
				Usage:       "Request the passed scope.",
				DefaultText: "all scopes allowed for the used mytoken",
				Destination: &atCommand.Scopes,
				Placeholder: "SCOPE",
			},
			&cli.StringSliceFlag{
				Name:        "aud",
				Aliases:     []string{"audience"},
				Usage:       "Request the passed audience.",
				Destination: &atCommand.Audiences,
				Placeholder: "AUD",
			},
			&cli.StringFlag{
				Name:        "out",
				Aliases:     []string{"o"},
				Usage:       "The access token will be printed to this output",
				Value:       "/dev/stdout",
				Destination: &atCommand.Out,
				Placeholder: "FILE",
			},
		),
	})
}

func getAT(context *cli.Context) error {
	atc := atCommand
	var comment string
	if context.Args().Len() > 0 {
		comment = context.Args().Get(0)
	}
	mytoken := config.Get().Mytoken
	provider, mToken := atc.Check()
	at, err := mytoken.GetAccessToken(mToken, provider.Issuer, atc.Scopes.Value(), atc.Audiences.Value(), comment)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(atc.Out, append([]byte(at), '\n'), 0600)
}
