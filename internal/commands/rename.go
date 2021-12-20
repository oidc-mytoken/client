package commands

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
)

var renameCommand = struct {
	Provider string
}{}

func init() {
	app.Commands = append(app.Commands, &cli.Command{
		Name:      "rename",
		Usage:     "Renames a stored mytoken",
		Action:    rename,
		ArgsUsage: "OLD_NAME NEW_NAME",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "provider",
				Aliases:     []string{"i", "issuer"},
				Usage:       "The name or issuer url of the OpenID provider for which a mytoken should be renamed",
				EnvVars:     []string{"MYTOKEN_PROVIDER"},
				Destination: &renameCommand.Provider,
				Placeholder: "PROVIDER",
			},
		},
	})
}

func rename(context *cli.Context) error {
	if context.Args().Len() != 2 {
		return fmt.Errorf("Old and new mytoken names must be given")
	}
	oldName := context.Args().Get(0)
	newName := context.Args().Get(1)
	pt := PTOptions{}
	pt.SetProvider(renameCommand.Provider)
	pt.SetName(oldName)
	p, err := pt.checkProvider()
	if err != nil {
		return err
	}
	entry, err := config.Get().GetTokenEntry(p.Issuer, oldName, pt.SetName)
	if err != nil {
		return err
	}
	entry.Name = newName
	config.Get().TokensFileContent.Remove(oldName, p.Issuer)
	config.Get().TokensFileContent.Add(entry, p.Issuer)
	return config.Get().TokensFileContent.Save()
}
