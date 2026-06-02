package commands

import (
	"context"
	"fmt"

	"github.com/oidc-mytoken/api/v0"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/color"
	"github.com/oidc-mytoken/client/internal/utils/tablewriter"
)

var tagsOptions = struct {
	MTOptions
	TagName    string
	NewTagName string
	Color      string
}{}

func initTags(parent *cli.Command) {
	cmd := &cli.Command{
		Name:  "tags",
		Usage: "View and manage your tags",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "List all your tags",
				Action: listTags,
				Flags:  getMTFlags(),
			},
			{
				Name:      "create",
				Usage:     "Create a new tag",
				ArgsUsage: "<name>",
				Action:    createTag,
				Flags: append(
					getMTFlags(),
					&cli.StringFlag{
						Name:        "color",
						Usage:       "Tag color (hex code or named color like 'red', 'blue')",
						Destination: &tagsOptions.Color,
					},
				),
			},
			{
				Name:      "update",
				Usage:     "Update an existing tag",
				ArgsUsage: "<name>",
				Action:    updateTag,
				Flags: append(
					getMTFlags(),
					&cli.StringFlag{
						Name:        "new-name",
						Usage:       "New name for the tag",
						Destination: &tagsOptions.NewTagName,
					},
					&cli.StringFlag{
						Name:        "color",
						Usage:       "New color for the tag (hex code or named color)",
						Destination: &tagsOptions.Color,
					},
				),
			},
			{
				Name: "delete",
				Aliases: []string{
					"rm",
					"remove",
				},
				Usage:     "Delete a tag",
				ArgsUsage: "<name>",
				Action:    deleteTag,
				Flags:     getMTFlags(),
			},
		},
	}
	parent.Commands = append(parent.Commands, cmd)
}

func listTags(_ context.Context, _ *cli.Command) error {
	if ssh := tagsOptions.SSH(); ssh != "" {
		res, err := doSSHParseJSON[struct {
			Tags []api.TagInfo `json:"tags"`
		}](ssh, api.SSHRequestTagsList, nil)
		if err != nil {
			return err
		}
		outputData := make([]tablewriter.TableWriter, len(res.Tags))
		for i, t := range res.Tags {
			outputData[i] = tableTagInfo(t)
		}
		tablewriter.PrintTableData(outputData)
		return nil
	}
	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.UserSettings.Tags.APIGet(mytoken)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	outputData := make([]tablewriter.TableWriter, len(res.Tags))
	for i, t := range res.Tags {
		outputData[i] = tableTagInfo(t)
	}
	tablewriter.PrintTableData(outputData)
	return nil
}

type tableTagInfo api.TagInfo

func (tableTagInfo) TableGetHeader() []string {
	return []string{
		"Color Block",
		"Tag",
		"Color (Hex)",
	}
}

func (t tableTagInfo) TableGetRow() []string {
	colorBlock := color.TerminalColorBlock(t.Color)
	return []string{
		colorBlock,
		string(t.Tag),
		t.Color,
	}
}

func createTag(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("tag name required")
	}
	tagName := cmd.Args().Get(0)

	var tagColor string
	if tagsOptions.Color != "" {
		normalizedColor, err := color.NormalizeColor(tagsOptions.Color)
		if err != nil {
			return fmt.Errorf("invalid color: %w", err)
		}
		tagColor = normalizedColor
	}

	if ssh := tagsOptions.SSH(); ssh != "" {
		req := SSHTagCreateRequest{Tag: api.Tag(tagName)}
		if tagColor != "" {
			req.Color = &tagColor
		}
		if err := doSSH(ssh, api.SSHRequestTagCreate, &req); err != nil {
			return err
		}
		fmt.Printf("Tag '%s' created successfully\n", tagName)
		return nil
	}

	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	err := mtServer.UserSettings.Tags.APICreate(mytoken, tagName, tagColor)
	if err != nil {
		return err
	}

	fmt.Printf("Tag '%s' created successfully\n", tagName)
	return nil
}

func updateTag(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("tag name required")
	}
	tagName := cmd.Args().Get(0)

	if tagsOptions.NewTagName == "" && tagsOptions.Color == "" {
		return fmt.Errorf("at least one of --new-name or --color must be provided")
	}

	var newColor string
	if tagsOptions.Color != "" {
		normalizedColor, err := color.NormalizeColor(tagsOptions.Color)
		if err != nil {
			return fmt.Errorf("invalid color: %w", err)
		}
		newColor = normalizedColor
	}

	if ssh := tagsOptions.SSH(); ssh != "" {
		req := SSHTagUpdateRequest{Tag: api.Tag(tagName)}
		if newColor != "" {
			req.Color = &newColor
		}
		if tagsOptions.NewTagName != "" {
			req.Name = &tagsOptions.NewTagName
		}
		if err := doSSH(ssh, api.SSHRequestTagUpdate, &req); err != nil {
			return err
		}
		fmt.Printf("Tag '%s' updated successfully\n", tagName)
		return nil
	}

	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.UserSettings.Tags.APIUpdate(mytoken, tagName, tagsOptions.NewTagName, newColor)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Tag '%s' updated successfully\n", tagName)
	return nil
}

func deleteTag(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("tag name required")
	}
	tagName := cmd.Args().Get(0)

	if ssh := tagsOptions.SSH(); ssh != "" {
		req := SSHTagDeleteRequest{Tag: api.Tag(tagName)}
		if err := doSSH(ssh, api.SSHRequestTagDelete, &req); err != nil {
			return err
		}
		fmt.Printf("Tag '%s' deleted successfully\n", tagName)
		return nil
	}

	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.UserSettings.Tags.APIDelete(mytoken, tagName)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Tag '%s' deleted successfully\n", tagName)
	return nil
}
