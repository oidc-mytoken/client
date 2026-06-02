package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
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
				Name:   "groups",
				Usage:  "List all available groups",
				Action: listGroups,
				Flags:  getMTFlags(),
			},
			{
				Name:    "list",
				Usage:   "List profiles grouped by group",
				Aliases: []string{"profiles"},
				Action:  listProfiles,
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
			{
				Name:    "list-all",
				Usage:   "List all profiles and templates grouped by group",
				Action:  listAll,
				Aliases: []string{"all"},
				Flags: append(
					getMTFlags(),
					&cli.StringSliceFlag{
						Name:        "groups",
						Usage:       "Filter to specific groups (can be used multiple times)",
						Destination: &profilesOptions.Groups,
					},
				),
			},
		},
	}
	app.Commands = append(app.Commands, cmd)
}

func listGroups(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()

	groups, err := mtServer.ProfilesAndTemplates.APIGetGroups()
	if err != nil {
		return err
	}

	for _, group := range groups {
		fmt.Println(group)
	}
	return nil
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
		profiles, err := mtServer.ProfilesAndTemplates.APIGetProfiles(group)
		if err != nil || len(profiles) == 0 {
			continue
		}

		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

		for _, profile := range profiles {
			fmt.Fprintf(w, "  %s\n", profile.Name)
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
		caps, err := mtServer.ProfilesAndTemplates.APIGetCapabilities(group)
		if err != nil || len(caps) == 0 {
			continue
		}

		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

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
		restrs, err := mtServer.ProfilesAndTemplates.APIGetRestrictions(group)
		if err != nil || len(restrs) == 0 {
			continue
		}

		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

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
		rots, err := mtServer.ProfilesAndTemplates.APIGetRotation(group)
		if err != nil || len(rots) == 0 {
			continue
		}

		fmt.Fprintf(w, "\nGroup: %s\n", group)
		fmt.Fprintln(w, "----------")

		for _, rot := range rots {
			fmt.Fprintf(w, "  %s\n", rot.Name)
		}
	}

	w.Flush()
	return nil
}

func listAll(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()

	groups, err := getGroupsToQuery(profilesOptions.Groups, mtServer)
	if err != nil {
		return err
	}

	allProfiles := make(map[string][]string)
	allCaps := make(map[string][]string)
	allRestrs := make(map[string][]string)
	allRots := make(map[string][]string)

	for _, group := range groups {
		profiles, err := mtServer.ProfilesAndTemplates.APIGetProfiles(group)
		if err == nil && len(profiles) > 0 {
			for _, p := range profiles {
				allProfiles[group] = append(allProfiles[group], p.Name)
			}
		}

		caps, err := mtServer.ProfilesAndTemplates.APIGetCapabilities(group)
		if err == nil && len(caps) > 0 {
			for _, c := range caps {
				allCaps[group] = append(allCaps[group], c.Name)
			}
		}

		restrs, err := mtServer.ProfilesAndTemplates.APIGetRestrictions(group)
		if err == nil && len(restrs) > 0 {
			for _, r := range restrs {
				allRestrs[group] = append(allRestrs[group], r.Name)
			}
		}

		rots, err := mtServer.ProfilesAndTemplates.APIGetRotation(group)
		if err == nil && len(rots) > 0 {
			for _, r := range rots {
				allRots[group] = append(allRots[group], r.Name)
			}
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	printSection := func(title string, data map[string][]string) {
		if len(data) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s:\n", title)
		fmt.Fprintln(w, strings.Repeat("=", len(title)))
		for group, items := range data {
			fmt.Fprintf(w, "\n  Group: %s\n", group)
			fmt.Fprintln(w, "  ----------")
			for _, item := range items {
				fmt.Fprintf(w, "    - %s\n", item)
			}
		}
	}

	printSection("Profiles", allProfiles)
	printSection("Capabilities", allCaps)
	printSection("Restrictions", allRestrs)
	printSection("Rotation", allRots)

	w.Flush()
	return nil
}
