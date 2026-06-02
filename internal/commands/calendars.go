package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/Songmu/prompter"
	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/color"
	"github.com/oidc-mytoken/client/internal/utils/tablewriter"
)

var calendarsOptions = struct {
	MTOptions
	CalendarID  string
	Description string
	Tags        []string
	AddTags     []string
	RemoveTags  []string
	MomID       string
	Comment     string
	Interactive bool
	Force       bool
}{}

func init() {
	app.Commands = append(
		app.Commands, &cli.Command{
			Name:    "calendars",
			Aliases: []string{"calendar"},
			Usage:   "View and manage your calendars",
			Flags:   getMTFlags(),
			Commands: []*cli.Command{
				{
					Name:   "list",
					Usage:  "List all your calendars",
					Action: listCalendars,
					Flags:  getMTFlags(),
				},
				{
					Name:    "create",
					Aliases: []string{"new"},
					Usage:   "Create a new calendar",
					Action:  createCalendar,
					Flags: append(
						getMTFlags(),
						&cli.StringFlag{
							Name:        "description",
							Usage:       "Calendar description",
							Destination: &calendarsOptions.Description,
						},
						&cli.StringSliceFlag{
							Name:        "tags",
							Usage:       "Tags for the calendar (comma-separated or repeat flag)",
							Destination: &calendarsOptions.Tags,
						},
						&cli.BoolFlag{
							Name:        "interactive",
							Aliases:     []string{"i"},
							Usage:       "Interactive mode with guided prompts",
							Destination: &calendarsOptions.Interactive,
						},
					),
				},
				{
					Name:      "update",
					Usage:     "Update calendar description and/or tags",
					ArgsUsage: "<calendar-id>",
					Action:    updateCalendar,
					Flags: append(
						getMTFlags(),
						&cli.StringFlag{
							Name:        "description",
							Usage:       "New calendar description",
							Destination: &calendarsOptions.Description,
						},
						&cli.StringSliceFlag{
							Name:        "add-tags",
							Usage:       "Add these tags",
							Destination: &calendarsOptions.AddTags,
						},
						&cli.StringSliceFlag{
							Name:        "remove-tags",
							Usage:       "Remove these tags",
							Destination: &calendarsOptions.RemoveTags,
						},
					),
				},
				{
					Name: "delete",
					Aliases: []string{
						"rm",
						"remove",
					},
					Usage:     "Delete a calendar",
					ArgsUsage: "<calendar-id>",
					Action:    deleteCalendar,
					Flags: append(
						getMTFlags(),
						&cli.BoolFlag{
							Name:        "force",
							Aliases:     []string{"f"},
							Usage:       "Skip confirmation prompt",
							Destination: &calendarsOptions.Force,
						},
					),
				},
				{
					Name:      "subscribe",
					Aliases:   []string{"add"},
					Usage:     "Subscribe a mytoken to a calendar",
					ArgsUsage: "<calendar-id>",
					Action:    subscribeToCalendar,
					Flags: append(
						getMTFlags(),
						&cli.StringFlag{
							Name:        "mom-id",
							Usage:       "MOM-ID of the token to subscribe",
							Destination: &calendarsOptions.MomID,
						},
						&cli.StringFlag{
							Name:        "comment",
							Usage:       "Comment for the subscription",
							Destination: &calendarsOptions.Comment,
						},
					),
				},
				{
					Name:      "unsubscribe",
					Aliases:   []string{"remove"},
					Usage:     "Unsubscribe from a calendar",
					ArgsUsage: "<calendar-id>",
					Action:    unsubscribeFromCalendar,
					Flags: append(
						getMTFlags(),
						&cli.StringFlag{
							Name:        "mom-id",
							Usage:       "MOM-ID of the token to unsubscribe",
							Destination: &calendarsOptions.MomID,
						},
					),
				},
			},
		},
	)
}

func listCalendars(_ context.Context, _ *cli.Command) error {
	if ssh := calendarsOptions.SSH(); ssh != "" {
		res, err := doSSHParseJSON[api.CalendarListResponse](ssh, api.SSHRequestCalendars, nil)
		if err != nil {
			return err
		}
		outputData := make([]tablewriter.TableWriter, len(res.Calendars))
		for i, c := range res.Calendars {
			outputData[i] = tableCalendarInfo(c)
		}
		tablewriter.PrintTableData(outputData)
		return nil
	}
	mytoken := calendarsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.Calendars.APIList(mytoken)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	outputData := make([]tablewriter.TableWriter, len(res.Calendars))
	for i, c := range res.Calendars {
		outputData[i] = tableCalendarInfo(c)
	}
	tablewriter.PrintTableData(outputData)
	return nil
}

type tableCalendarInfo api.CalendarInfo

func (tableCalendarInfo) TableGetHeader() []string {
	return []string{
		"ID",
		"Description",
		"Tags",
		"ICS Path",
		"Subscribed Tokens",
	}
}

func (c tableCalendarInfo) TableGetRow() []string {
	tags := ""
	if len(c.Tags) > 0 {
		tagStrs := make([]string, len(c.Tags))
		for i, t := range c.Tags {
			tagStrs[i] = color.ColorizeText(string(t.Tag), t.Color)
		}
		tags = strings.Join(tagStrs, ", ")
	}

	subscribedCount := fmt.Sprintf("%d", len(c.SubscribedTokens))

	return []string{
		c.ID,
		c.Description,
		tags,
		c.ICSPath,
		subscribedCount,
	}
}

func createCalendar(_ context.Context, _ *cli.Command) error {
	mytoken := calendarsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	if calendarsOptions.Interactive {
		if err := interactiveCreateCalendar(mytoken, mtServer); err != nil {
			return err
		}
		return nil
	}

	tags := parseStringSlice(calendarsOptions.Tags)

	if ssh := calendarsOptions.SSH(); ssh != "" {
		req := api.CreateCalendarRequest{
			Description: calendarsOptions.Description,
			Tags:        stringSliceToTags(tags),
		}
		createRes, err := doSSHParseJSON[struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			ICSPath     string `json:"ics_path"`
		}](ssh, api.SSHRequestCalendarCreate, &req)
		if err != nil {
			return err
		}
		fmt.Printf("\n✓ Calendar created successfully! ID: %s\n", createRes.ID)
		return nil
	}

	apiTags, err := getOrCreateTags(mytoken, mtServer, tags)
	if err != nil {
		return err
	}

	req := api.CreateCalendarRequest{
		Description: calendarsOptions.Description,
		Tags:        apiTags,
	}

	res, err := mtServer.Calendars.APICreate(mytoken, req)
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ Calendar created successfully! ID: %s\n", res.ID)
	return nil
}

func interactiveCreateCalendar(mytoken string, mtServer *mytokenlib.MytokenServer) error {
	fmt.Println("=== Interactive Calendar Creation ===")
	fmt.Println()

	// Step 1: Description
	calendarsOptions.Description = prompter.Prompt("Enter calendar description", "")

	// Step 2: Tags
	existingTags, err := mtServer.UserSettings.Tags.APIGet(mytoken)
	if err != nil {
		return err
	}
	if len(existingTags.Tags) > 0 {
		fmt.Println("\nAvailable tags:")
		for _, tag := range existingTags.Tags {
			fmt.Printf("  %s\n", color.ColorizeText(string(tag.Tag), tag.Color))
		}
	}
	tagsInput := prompter.Prompt("Add tags (comma-separated, or empty to skip)", "")
	tags := parseStringSlice(strings.Split(tagsInput, ","))
	apiTags, err := getOrCreateTags(mytoken, mtServer, tags)
	if err != nil {
		return err
	}

	// Step 3: Preview and confirm
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Description: %s\n", calendarsOptions.Description)
	if len(apiTags) > 0 {
		tagStrs := make([]string, len(apiTags))
		for i, t := range apiTags {
			tagStrs[i] = string(t)
		}
		fmt.Printf("Tags: %s\n", strings.Join(tagStrs, ", "))
	}

	if !prompter.YN("\nConfirm creation?", true) {
		fmt.Println("Cancelled.")
		return nil
	}

	// Execute creation
	req := api.CreateCalendarRequest{
		Description: calendarsOptions.Description,
		Tags:        apiTags,
	}

	res, err := mtServer.Calendars.APICreate(mytoken, req)
	if err != nil {
		return err
	}

	fmt.Printf("\n✓ Calendar created successfully! ID: %s\n", res.ID)
	return nil
}

func updateCalendar(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("calendar-id is required")
	}
	calendarID := cmd.Args().Get(0)

	addTags := parseStringSlice(calendarsOptions.AddTags)
	removeTags := parseStringSlice(calendarsOptions.RemoveTags)

	if calendarsOptions.Description == "" && len(addTags) == 0 && len(removeTags) == 0 {
		return fmt.Errorf("at least one of --description, --add-tags, or --remove-tags must be provided")
	}

	if ssh := calendarsOptions.SSH(); ssh != "" {
		listRes, err := doSSHParseJSON[api.CalendarListResponse](ssh, api.SSHRequestCalendars, nil)
		if err != nil {
			return err
		}

		var currentCalendar *api.CalendarInfo
		for _, c := range listRes.Calendars {
			if c.ID == calendarID {
				currentCalendar = &c
				break
			}
		}
		if currentCalendar == nil {
			return fmt.Errorf("calendar with ID '%s' not found", calendarID)
		}

		newDescription := calendarsOptions.Description
		if newDescription == "" {
			newDescription = currentCalendar.Description
		}

		newTags := make(map[api.Tag]bool)
		for _, t := range currentCalendar.Tags {
			newTags[t.Tag] = true
		}

		apiAddTags, err := getOrCreateTagsViaSSH(ssh, addTags)
		if err != nil {
			return err
		}
		for _, t := range apiAddTags {
			newTags[t] = true
		}

		for _, tagName := range removeTags {
			delete(newTags, api.Tag(tagName))
		}

		finalTags := make([]api.Tag, 0, len(newTags))
		for t := range newTags {
			finalTags = append(finalTags, t)
		}

		finalTagStrings := make([]string, len(finalTags))
		for i, t := range finalTags {
			finalTagStrings[i] = string(t)
		}

		req := SSHCalendarUpdateRequest{
			CalendarID: calendarID,
			CreateCalendarRequest: api.CreateCalendarRequest{
				Description: newDescription,
				Tags:        stringSliceToTags(finalTagStrings),
			},
		}
		return doSSH(ssh, api.SSHRequestCalendarUpdate, &req)
	}

	mytoken := calendarsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	// Get current calendar state
	listRes, err := mtServer.Calendars.APIList(mytoken)
	if err != nil {
		return err
	}

	var currentCalendar *api.CalendarInfo
	for _, c := range listRes.Calendars {
		if c.ID == calendarID {
			currentCalendar = &c
			break
		}
	}
	if currentCalendar == nil {
		return fmt.Errorf("calendar with ID '%s' not found", calendarID)
	}

	// Build new description
	newDescription := calendarsOptions.Description
	if newDescription == "" {
		newDescription = currentCalendar.Description
	}

	// Build new tags list
	newTags := make(map[api.Tag]bool)
	for _, t := range currentCalendar.Tags {
		newTags[t.Tag] = true
	}

	// Add tags (auto-create if needed)
	apiAddTags, err := getOrCreateTags(mytoken, mtServer, addTags)
	if err != nil {
		return err
	}
	for _, t := range apiAddTags {
		newTags[t] = true
	}

	// Remove tags
	for _, tagName := range removeTags {
		delete(newTags, api.Tag(tagName))
	}

	// Convert map back to slice
	finalTags := make([]api.Tag, 0, len(newTags))
	for t := range newTags {
		finalTags = append(finalTags, t)
	}

	req := api.CreateCalendarRequest{
		Description: newDescription,
		Tags:        finalTags,
	}

	res, err := mtServer.Calendars.APIUpdate(mytoken, calendarID, req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Calendar '%s' updated successfully\n", calendarID)
	return nil
}

func deleteCalendar(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("calendar-id is required")
	}
	calendarID := cmd.Args().Get(0)

	if !calendarsOptions.Force {
		prompt := fmt.Sprintf("Are you sure you want to delete calendar %s?", calendarID)
		if !prompter.YN(prompt, false) {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	if ssh := calendarsOptions.SSH(); ssh != "" {
		req := SSHCalendarIDRequest{CalendarID: calendarID}
		return doSSH(ssh, api.SSHRequestCalendarDelete, &req)
	}

	mytoken := calendarsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.Calendars.APIDelete(mytoken, calendarID)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Calendar '%s' deleted successfully\n", calendarID)
	return nil
}

func subscribeToCalendar(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("calendar-id is required")
	}
	calendarID := cmd.Args().Get(0)

	if ssh := calendarsOptions.SSH(); ssh != "" {
		req := SSHCalendarSubscriptionRequest{
			CalendarID: calendarID,
			AddMytokenToCalendarRequest: api.AddMytokenToCalendarRequest{
				MomID:   calendarsOptions.MomID,
				Comment: calendarsOptions.Comment,
			},
		}
		return doSSH(ssh, api.SSHRequestCalendarAddMytoken, &req)
	}

	mytoken := calendarsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	req := api.AddMytokenToCalendarRequest{
		MomID:   calendarsOptions.MomID,
		Comment: calendarsOptions.Comment,
	}

	res, err := mtServer.Calendars.APISubscribe(mytoken, calendarID, req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Successfully subscribed to calendar '%s'\n", calendarID)
	return nil
}

func unsubscribeFromCalendar(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("calendar-id is required")
	}
	calendarID := cmd.Args().Get(0)

	if ssh := calendarsOptions.SSH(); ssh != "" {
		req := SSHCalendarSubscriptionRequest{
			CalendarID: calendarID,
			AddMytokenToCalendarRequest: api.AddMytokenToCalendarRequest{
				MomID: calendarsOptions.MomID,
			},
		}
		return doSSH(ssh, api.SSHRequestCalendarRemoveMytoken, &req)
	}

	mytoken := calendarsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.Calendars.APIUnsubscribe(mytoken, calendarID, calendarsOptions.MomID)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Successfully unsubscribed from calendar '%s'\n", calendarID)
	return nil
}
