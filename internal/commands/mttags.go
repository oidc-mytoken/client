package commands

import (
	"context"
	"fmt"

	"github.com/oidc-mytoken/api/v0"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
)

var mtTagsOptions = struct {
	MTOptions
	TagName         string
	MOMID           string
	IncludeChildren bool
}{}

func init() {
	cmd := &cli.Command{
		Name:  "tags",
		Usage: "Manage tags on mytokens",
		Commands: []*cli.Command{
			{
				Name:      "add",
				Usage:     "Add a tag to a mytoken",
				ArgsUsage: "<tag>",
				Action:    addMTTag,
				Flags: append(
					getMTFlags(),
					&cli.StringFlag{
						Name:        "mom-id",
						Usage:       "Target mytoken by mom_id",
						Destination: &mtTagsOptions.MOMID,
					},
					&cli.BoolFlag{
						Name:        "include-children",
						Usage:       "Apply to children tokens",
						Destination: &mtTagsOptions.IncludeChildren,
					},
				),
			},
			{
				Name: "remove",
				Aliases: []string{
					"rm",
					"delete",
				},
				Usage:     "Remove a tag from a mytoken",
				ArgsUsage: "<tag>",
				Action:    removeMTTag,
				Flags: append(
					getMTFlags(),
					&cli.StringFlag{
						Name:        "mom-id",
						Usage:       "Target mytoken by mom_id",
						Destination: &mtTagsOptions.MOMID,
					},
					&cli.BoolFlag{
						Name:        "include-children",
						Usage:       "Apply to children tokens",
						Destination: &mtTagsOptions.IncludeChildren,
					},
				),
			},
		},
	}

	// Add as subcommand to MT command
	mtCmd := findCommand(app.Commands, "MT")
	if mtCmd == nil {
		mtCmd = findCommand(app.Commands, "mt")
	}
	if mtCmd == nil {
		mtCmd = findCommand(app.Commands, "mytoken")
	}
	if mtCmd != nil {
		listCmd := &cli.Command{
			Name:    "list-mytokens",
			Aliases: []string{"list"},
			Usage:   "List all mytokens",
			Action:  listMytokens,
			Flags: append(
				getMTFlags(),
				&cli.BoolFlag{
					Name:  "include-mom-id",
					Usage: "Include the MOM-ID column in the output",
				},
			),
		}
		mtCmd.Commands = append(mtCmd.Commands, cmd, listCmd)
	}
}

func addMTTag(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("tag name required")
	}
	tagName := cmd.Args().Get(0)
	mytoken := mtTagsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	req := api.AddTagToMytokenRequest{
		Tag:             api.Tag(tagName),
		Mytoken:         mytoken,
		MOMID:           mtTagsOptions.MOMID,
		IncludeChildren: mtTagsOptions.IncludeChildren,
	}

	res, err := mtServer.Mytoken.Tags().APIAdd(req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Tag '%s' added successfully\n", tagName)
	return nil
}

func removeMTTag(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("tag name required")
	}
	tagName := cmd.Args().Get(0)
	mytoken := mtTagsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	req := api.RemoveTagFromMytokenRequest{
		Tag:             api.Tag(tagName),
		Mytoken:         mytoken,
		MOMID:           mtTagsOptions.MOMID,
		IncludeChildren: mtTagsOptions.IncludeChildren,
	}

	res, err := mtServer.Mytoken.Tags().APIRemove(req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Tag '%s' removed successfully\n", tagName)
	return nil
}
