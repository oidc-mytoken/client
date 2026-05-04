package commands

import (
	"context"
	"fmt"

	"github.com/oidc-mytoken/api/v0"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/tablewriter"
)

func initGrants(parent *cli.Command) {
	grantsFlags := getMTFlags()
	subCommandFlags := getMTFlags()
	cmd := &cli.Command{
		Name:    "grants",
		Aliases: []string{"grant-types"},
		Usage:   "View and manage your user grant types",
		Flags:   grantsFlags,
		Commands: []*cli.Command{
			{
				Name:    "list",
				Aliases: []string{"view"},
				Usage:   "Lists your available grant types",
				Action:  listGrants,
				Flags:   subCommandFlags,
			},
			{
				Name:      "enable",
				ArgsUsage: "GRANT",
				Usage:     "Enables a grant type",
				Action:    enableGrant,
				Flags:     subCommandFlags,
			},
			{
				Name:      "disable",
				ArgsUsage: "GRANT",
				Usage:     "Disables a grant type",
				Action:    disableGrant,
				Flags:     subCommandFlags,
			},
		},
	}
	parent.Commands = append(parent.Commands, cmd)
	initSSHGrant(cmd)
}

func listGrants(_ context.Context, _ *cli.Command) error {
	mytoken := settingsOptions.MustGetToken()
	res, err := config.Get().Mytoken().UserSettings.Grants.APIGet(mytoken)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}
	outputData := make([]tablewriter.TableWriter, len(res.GrantTypes))
	for i, d := range res.GrantTypes {
		outputData[i] = tableGrantTypeInfo(d)
	}
	tablewriter.PrintTableData(outputData)
	return nil
}

type tableGrantTypeInfo api.GrantTypeInfo

func (tableGrantTypeInfo) TableGetHeader() []string {
	return []string{
		"Grant Type",
		"Status",
	}
}

func (i tableGrantTypeInfo) TableGetRow() []string {
	const enabled = "Enabled"
	const disabled = "Disabled"
	status := disabled
	if i.Enabled {
		status = enabled
	}
	return []string{
		i.GrantType,
		status,
	}
}

func enableGrant(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 1 {
		return fmt.Errorf("Must provide exactly one grant to enable")
	}
	grant := cmd.Args().Get(0)
	mytoken := settingsOptions.MustGetToken()
	res, err := config.Get().Mytoken().UserSettings.Grants.APIEnableGrant(mytoken, grant)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}
	fmt.Printf("Grant '%s' enabled\n", grant)
	return nil
}

func disableGrant(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 1 {
		return fmt.Errorf("Must provide exactly one grant to disable")
	}
	grant := cmd.Args().Get(0)
	mytoken := settingsOptions.MustGetToken()
	res, err := config.Get().Mytoken().UserSettings.Grants.APIDisableGrant(mytoken, grant)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}
	fmt.Printf("Grant '%s' disabled\n", grant)
	return nil
}
