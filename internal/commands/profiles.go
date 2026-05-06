package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
)

var profilesOptions = struct {
	MTOptions
	Groups []string
}{}

func init() {
	cmd := &cli.Command{
		Name:  "profiles",
		Usage: "List server-side profiles and templates",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "List all profiles grouped by group",
				Action: listProfiles,
				Flags: append(
					getMTFlags(),
					&cli.StringSliceFlag{
						Name:        "groups",
						Usage:       "Filter to specific groups (can be used multiple times)",
						Destination: &profilesOptions.Groups,
					},
				),
			},
			{
				Name:   "capabilities",
				Usage:  "List capability templates grouped by group",
				Action: listCapabilities,
				Flags: append(
					getMTFlags(),
					&cli.StringSliceFlag{
						Name:        "groups",
						Usage:       "Filter to specific groups",
						Destination: &profilesOptions.Groups,
					},
				),
			},
			{
				Name:   "restrictions",
				Usage:  "List restriction templates grouped by group",
				Action: listRestrictions,
				Flags: append(
					getMTFlags(),
					&cli.StringSliceFlag{
						Name:        "groups",
						Usage:       "Filter to specific groups",
						Destination: &profilesOptions.Groups,
					},
				),
			},
			{
				Name:   "rotation",
				Usage:  "List rotation templates grouped by group",
				Action: listRotation,
				Flags: append(
					getMTFlags(),
					&cli.StringSliceFlag{
						Name:        "groups",
						Usage:       "Filter to specific groups",
						Destination: &profilesOptions.Groups,
					},
				),
			},
		},
	}
	app.Commands = append(app.Commands, cmd)
}

func getGroupsToQuery(requestedGroups []string, mtServer *mytokenlib.MytokenServer) ([]string, error) {
	if len(requestedGroups) > 0 {
		return requestedGroups, nil
	}

	// Fetch all groups
	groups, err := mtServer.ProfilesAndTemplates.APIGetGroups()
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func listProfiles(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()

	groups, err := getGroupsToQuery(profilesOptions.Groups, mtServer)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	for _, group := range groups {
		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

		// Get capabilities
		caps, err := mtServer.ProfilesAndTemplates.APIGetCapabilities(group)
		if err == nil && len(caps) > 0 {
			fmt.Fprintln(w, "Capabilities:")
			for _, cap := range caps {
				fmt.Fprintf(w, "  - %s\n", cap.Name)
			}
		}

		// Get restrictions
		restrs, err := mtServer.ProfilesAndTemplates.APIGetRestrictions(group)
		if err == nil && len(restrs) > 0 {
			fmt.Fprintln(w, "Restrictions:")
			for _, restr := range restrs {
				fmt.Fprintf(w, "  - %s\n", restr.Name)
			}
		}

		// Get rotation
		rots, err := mtServer.ProfilesAndTemplates.APIGetRotation(group)
		if err == nil && len(rots) > 0 {
			fmt.Fprintln(w, "Rotation:")
			for _, rot := range rots {
				fmt.Fprintf(w, "  - %s\n", rot.Name)
			}
		}
	}

	w.Flush()
	return nil
}

func listCapabilities(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()

	groups, err := getGroupsToQuery(profilesOptions.Groups, mtServer)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	for _, group := range groups {
		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

		caps, err := mtServer.ProfilesAndTemplates.APIGetCapabilities(group)
		if err != nil {
			continue
		}

		for _, cap := range caps {
			fmt.Fprintf(w, "  %s\n", cap.Name)
		}
	}

	w.Flush()
	return nil
}

func listRestrictions(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()

	groups, err := getGroupsToQuery(profilesOptions.Groups, mtServer)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	for _, group := range groups {
		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

		restrs, err := mtServer.ProfilesAndTemplates.APIGetRestrictions(group)
		if err != nil {
			continue
		}

		for _, restr := range restrs {
			fmt.Fprintf(w, "  %s\n", restr.Name)
		}
	}

	w.Flush()
	return nil
}

func listRotation(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()

	groups, err := getGroupsToQuery(profilesOptions.Groups, mtServer)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	for _, group := range groups {
		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

		rots, err := mtServer.ProfilesAndTemplates.APIGetRotation(group)
		if err != nil {
			continue
		}

		for _, rot := range rots {
			fmt.Fprintf(w, "  %s\n", rot.Name)
		}
	}

	w.Flush()
	return nil
}
