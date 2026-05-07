package commands

import (
	"context"
	"fmt"
	"regexp"

	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/color"
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
	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.UserSettings.Tags.APIGet(mytoken)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	// Print header
	fmt.Println("COLOR    TAG                       Color (Hex)")
	fmt.Println("-------- ------------------------- --------------------")

	// ANSI escape code regex to strip for width calculation
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)

	// Print tags with color blocks
	for _, tag := range res.Tags {
		colorBlock := color.TerminalColorBlock(tag.Color)
		// Strip ANSI codes to get actual visual width of color block (should be 2 spaces)
		visualBlock := ansiRegex.ReplaceAllString(colorBlock, "")
		// Calculate padding needed: we want the color block to take 8 chars total (like "--------")
		padding := 8 - len(visualBlock)
		paddingStr := ""
		if padding > 0 {
			for i := 0; i < padding; i++ {
				paddingStr += " "
			}
		}
		fmt.Printf("%s%s  %-24s  %s\n", colorBlock, paddingStr, tag.Tag, tag.Color)
	}
	return nil
}

func createTag(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("tag name required")
	}
	tagName := cmd.Args().Get(0)
	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	var tagColor string
	if tagsOptions.Color != "" {
		normalizedColor, err := color.NormalizeColor(tagsOptions.Color)
		if err != nil {
			return fmt.Errorf("invalid color: %w", err)
		}
		tagColor = normalizedColor
	}

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
	mytoken := settingsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

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
