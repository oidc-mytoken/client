package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/Songmu/prompter"
	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/urfave/cli/v3"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/color"
	"github.com/oidc-mytoken/client/internal/utils/tablewriter"
)

var notificationsOptions = struct {
	MTOptions
	ManagementCode      string
	MOMID               string
	IncludeChildren     bool
	NotificationType    string
	NotificationClasses []string
	UserWide            bool
	Tags                []string
	Comment             string
	AddClasses          []string
	RemoveClasses       []string
	AddTags             []string
	RemoveTags          []string
	Interactive         bool
	Force               bool
}{}

func init() {
	app.Commands = append(
		app.Commands, &cli.Command{
			Name:    "notifications",
			Aliases: []string{"notify"},
			Usage:   "View and manage your notifications",
			Flags:   getMTFlags(),
			Commands: []*cli.Command{
				{
					Name:   "list",
					Usage:  "List all your notifications",
					Action: listNotifications,
					Flags:  getMTFlags(),
				},
				{
					Name: "create",
					Aliases: []string{
						"subscribe",
						"new",
					},
					Usage:  "Create a new notification subscription",
					Action: createNotification,
					Flags: append(
						getMTFlags(),
						&cli.StringFlag{
							Name:        "type",
							Usage:       "Notification type (mail, ics_invite)",
							Destination: &notificationsOptions.NotificationType,
						},
						&cli.StringSliceFlag{
							Name:        "classes",
							Usage:       "Notification classes (comma-separated or repeat flag)",
							Destination: &notificationsOptions.NotificationClasses,
						},
						&cli.BoolFlag{
							Name:        "user-wide",
							Usage:       "Make this notification user-wide",
							Destination: &notificationsOptions.UserWide,
						},
						&cli.StringSliceFlag{
							Name:        "tags",
							Usage:       "Tags for the notification (comma-separated or repeat flag)",
							Destination: &notificationsOptions.Tags,
						},
						&cli.StringFlag{
							Name:        "comment",
							Usage:       "Comment (only for ics_invite type)",
							Destination: &notificationsOptions.Comment,
						},
						&cli.BoolFlag{
							Name:        "interactive",
							Aliases:     []string{"i"},
							Usage:       "Interactive mode with guided prompts",
							Destination: &notificationsOptions.Interactive,
						},
					),
				},
				{
					Name:      "update",
					Usage:     "Update notification classes and/or tags",
					ArgsUsage: "<management-code>",
					Action:    updateNotification,
					Flags: append(
						getMTFlags(),
						&cli.StringSliceFlag{
							Name:        "add-classes",
							Usage:       "Add these notification classes",
							Destination: &notificationsOptions.AddClasses,
						},
						&cli.StringSliceFlag{
							Name:        "remove-classes",
							Usage:       "Remove these notification classes",
							Destination: &notificationsOptions.RemoveClasses,
						},
						&cli.StringSliceFlag{
							Name:        "add-tags",
							Usage:       "Add these tags",
							Destination: &notificationsOptions.AddTags,
						},
						&cli.StringSliceFlag{
							Name:        "remove-tags",
							Usage:       "Remove these tags",
							Destination: &notificationsOptions.RemoveTags,
						},
					),
				},
				{
					Name: "delete",
					Aliases: []string{
						"rm",
						"remove",
					},
					Usage:     "Delete a notification",
					ArgsUsage: "<management-code>",
					Action:    deleteNotification,
					Flags: append(
						getMTFlags(),
						&cli.BoolFlag{
							Name:        "force",
							Aliases:     []string{"f"},
							Usage:       "Skip confirmation prompt",
							Destination: &notificationsOptions.Force,
						},
					),
				},
				{
					Name:      "add-token",
					Usage:     "Add a token to a notification",
					ArgsUsage: "<management-code>",
					Action:    addTokenToNotification,
					Flags: append(
						getMTFlags(),
						&cli.StringFlag{
							Name:        "mom-id",
							Usage:       "MOM-ID of the token to add",
							Destination: &notificationsOptions.MOMID,
						},
						&cli.BoolFlag{
							Name:        "include-children",
							Usage:       "Include child tokens",
							Destination: &notificationsOptions.IncludeChildren,
						},
					),
				},
				{
					Name:      "remove-token",
					Usage:     "Remove a token from a notification",
					ArgsUsage: "<management-code>",
					Action:    removeTokenFromNotification,
					Flags: append(
						getMTFlags(),
						&cli.StringFlag{
							Name:        "mom-id",
							Usage:       "MOM-ID of the token to remove",
							Destination: &notificationsOptions.MOMID,
						},
					),
				},
			},
		},
	)
}

func parseStringSlice(input []string) []string {
	var result []string
	for _, val := range input {
		parts := strings.Split(val, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
	}
	return result
}

func listNotifications(_ context.Context, _ *cli.Command) error {
	if ssh := notificationsOptions.SSH(); ssh != "" {
		res, err := doSSHParseJSON[api.NotificationsListResponse](ssh, api.SSHRequestNotifications, nil)
		if err != nil {
			return err
		}
		outputData := make([]tablewriter.TableWriter, len(res.Notifications))
		for i, n := range res.Notifications {
			outputData[i] = tableNotificationInfo(n)
		}
		tablewriter.PrintTableData(outputData)
		return nil
	}
	mytoken := notificationsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.Notifications.APIList(mytoken)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	outputData := make([]tablewriter.TableWriter, len(res.Notifications))
	for i, n := range res.Notifications {
		outputData[i] = tableNotificationInfo(n)
	}
	tablewriter.PrintTableData(outputData)
	return nil
}

type tableNotificationInfo api.NotificationInfo

func (tableNotificationInfo) TableGetHeader() []string {
	return []string{
		"Type",
		"Management Code",
		"Classes",
		"User Wide",
		"Tags",
		"Subscribed Tokens",
	}
}

func (n tableNotificationInfo) TableGetRow() []string {
	classes := make([]string, len(n.Classes))
	for i, c := range n.Classes {
		classes[i] = c.Name
	}

	tags := ""
	if len(n.Tags) > 0 {
		tagStrs := make([]string, len(n.Tags))
		for i, t := range n.Tags {
			tagStrs[i] = color.ColorizeText(string(t.Tag), t.Color)
		}
		tags = strings.Join(tagStrs, ", ")
	}

	var subscribedCount string
	if n.UserWide {
		subscribedCount = "all"
	} else if n.TotalSubscribedTokens > 0 {
		// Use TotalSubscribedTokens from backend (includes direct + tag-based)
		subscribedCount = fmt.Sprintf("%d", n.TotalSubscribedTokens)
	} else {
		// Fallback to direct count if TotalSubscribedTokens not set
		subscribedCount = fmt.Sprintf("%d", len(n.SubscribedTokens))
	}

	return []string{
		n.Type,
		n.ManagementCode,
		strings.Join(classes, ", "),
		fmt.Sprintf("%v", n.UserWide),
		tags,
		subscribedCount,
	}
}

func createNotification(_ context.Context, _ *cli.Command) error {
	mytoken := notificationsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	if notificationsOptions.Interactive {
		if err := interactiveCreateNotification(mytoken, mtServer); err != nil {
			return err
		}
		return nil
	}

	if notificationsOptions.NotificationType == "" {
		return fmt.Errorf("--type is required (mail or ics_invite)")
	}

	classes := parseStringSlice(notificationsOptions.NotificationClasses)
	if len(classes) == 0 {
		return fmt.Errorf("--classes is required")
	}

	tags := parseStringSlice(notificationsOptions.Tags)

	if ssh := notificationsOptions.SSH(); ssh != "" {
		req := api.SubscribeNotificationRequest{
			NotificationType:    notificationsOptions.NotificationType,
			NotificationClasses: parseNotificationClasses(classes),
			UserWide:            notificationsOptions.UserWide,
			Tags:                stringSliceToTags(tags),
			Comment:             notificationsOptions.Comment,
			MOMID:               notificationsOptions.MOMID,
		}
		createRes, err := doSSHParseJSON[struct {
			ManagementCode string `json:"management_code"`
		}](ssh, api.SSHRequestNotificationCreate, &req)
		if err != nil {
			return err
		}
		displayManagementCode(createRes.ManagementCode, "notification")
		return nil
	}

	apiTags, err := getOrCreateTags(mytoken, mtServer, tags)
	if err != nil {
		return err
	}

	req := api.SubscribeNotificationRequest{
		Mytoken:             mytoken,
		NotificationType:    notificationsOptions.NotificationType,
		NotificationClasses: parseNotificationClasses(classes),
		UserWide:            notificationsOptions.UserWide,
		Tags:                apiTags,
		Comment:             notificationsOptions.Comment,
	}

	res, err := mtServer.Notifications.APICreate(mytoken, req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	displayManagementCode(res.ManagementCode, "notification")
	return nil
}

func interactiveCreateNotification(mytoken string, mtServer *mytokenlib.MytokenServer) error {
	fmt.Println("=== Interactive Notification Creation ===")
	fmt.Println()

	// Step 1: Notification type
	types := []string{
		"mail",
		"ics_invite",
	}
	notificationsOptions.NotificationType = prompter.Choose(
		"Select notification type",
		types,
		"mail",
	)

	// Step 2: Show available classes and let user select
	displayAvailableNotificationClasses()
	classesInput := prompter.Prompt(
		"Enter notification classes (comma-separated)",
		"",
	)
	classes := parseStringSlice(strings.Split(classesInput, ","))
	if len(classes) == 0 {
		return fmt.Errorf("at least one notification class is required")
	}

	// Step 3: User-wide
	notificationsOptions.UserWide = prompter.YN("Make this notification user-wide?", false)

	// Step 4: Tags (skip if user-wide)
	var apiTags []api.Tag
	if !notificationsOptions.UserWide {
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
		apiTags, err = getOrCreateTags(mytoken, mtServer, tags)
		if err != nil {
			return err
		}
	}

	// Step 4: Comment for ics_invite
	if notificationsOptions.NotificationType == "ics_invite" {
		notificationsOptions.Comment = prompter.Prompt("Enter comment for ics_invite", "")
	}

	// Step 5: Preview and confirm
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Type: %s\n", notificationsOptions.NotificationType)
	fmt.Printf("Classes: %s\n", strings.Join(classes, ", "))
	fmt.Printf("User-wide: %v\n", notificationsOptions.UserWide)
	if !notificationsOptions.UserWide && len(apiTags) > 0 {
		tagStrs := make([]string, len(apiTags))
		for i, t := range apiTags {
			tagStrs[i] = string(t)
		}
		fmt.Printf("Tags: %s\n", strings.Join(tagStrs, ", "))
	}
	if notificationsOptions.Comment != "" {
		fmt.Printf("Comment: %s\n", notificationsOptions.Comment)
	}

	if !prompter.YN("\nConfirm creation?", true) {
		fmt.Println("Cancelled.")
		return nil
	}

	// Execute creation
	req := api.SubscribeNotificationRequest{
		Mytoken:             mytoken,
		NotificationType:    notificationsOptions.NotificationType,
		NotificationClasses: parseNotificationClasses(classes),
		UserWide:            notificationsOptions.UserWide,
		Tags:                apiTags,
		Comment:             notificationsOptions.Comment,
	}

	res, err := mtServer.Notifications.APICreate(mytoken, req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	displayManagementCode(res.ManagementCode, "notification")
	return nil
}

func displayAvailableNotificationClasses() {
	fmt.Println("\nAvailable notification classes:")
	allClasses := api.AllNotificationClasses
	for _, nc := range allClasses {
		children := nc.GetChildren()
		if len(children) > 0 {
			fmt.Printf("  %s\n", nc.Name)
			for _, child := range children {
				fmt.Printf("    └─ %s\n", child.Name)
				grandchildren := child.GetChildren()
				for _, gc := range grandchildren {
					fmt.Printf("        └─ %s\n", gc.Name)
				}
			}
		} else {
			fmt.Printf("  %s\n", nc.Name)
		}
	}
	fmt.Println()
}

func parseNotificationClasses(classNames []string) api.NotificationClasses {
	var result api.NotificationClasses
	for _, name := range classNames {
		nc := api.NewNotificationClass(name)
		result = append(result, nc)
	}
	return result
}

func getOrCreateTags(mytoken string, mtServer *mytokenlib.MytokenServer, tagNames []string) ([]api.Tag, error) {
	var result []api.Tag

	// Get existing tags
	existingResp, err := mtServer.UserSettings.Tags.APIGet(mytoken)
	if err != nil {
		return nil, err
	}

	existingTagMap := make(map[string]bool)
	for _, tag := range existingResp.Tags {
		existingTagMap[string(tag.Tag)] = true
	}

	// Process requested tags
	for _, tagName := range tagNames {
		if tagName == "" {
			continue
		}

		// If tag doesn't exist, create it with default color
		if !existingTagMap[tagName] {
			err := mtServer.UserSettings.Tags.APICreate(mytoken, tagName, "")
			if err != nil {
				return nil, fmt.Errorf("failed to create tag '%s': %w", tagName, err)
			}
			existingTagMap[tagName] = true
		}
		result = append(result, api.Tag(tagName))
	}

	return result, nil
}

func displayManagementCode(code, entityType string) {
	fmt.Printf(
		"\n✓ %s created successfully! Management code: %s\n", cases.Title(language.English).String(entityType), code,
	)
}

func updateNotification(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("management-code is required")
	}
	managementCode := cmd.Args().Get(0)

	addClasses := parseStringSlice(notificationsOptions.AddClasses)
	removeClasses := parseStringSlice(notificationsOptions.RemoveClasses)
	addTags := parseStringSlice(notificationsOptions.AddTags)
	removeTags := parseStringSlice(notificationsOptions.RemoveTags)

	if len(addClasses) == 0 && len(removeClasses) == 0 && len(addTags) == 0 && len(removeTags) == 0 {
		return fmt.Errorf("at least one of --add-classes, --remove-classes, --add-tags, or --remove-tags must be provided")
	}

	if ssh := notificationsOptions.SSH(); ssh != "" {
		listRes, err := doSSHParseJSON[api.NotificationsListResponse](ssh, api.SSHRequestNotifications, nil)
		if err != nil {
			return err
		}

		var currentNotification *api.NotificationInfo
		for _, n := range listRes.Notifications {
			if n.ManagementCode == managementCode {
				currentNotification = &n
				break
			}
		}
		if currentNotification == nil {
			return fmt.Errorf("notification with management code '%s' not found", managementCode)
		}

		newClasses := make(map[string]*api.NotificationClass)
		for _, c := range currentNotification.Classes {
			newClasses[c.Name] = c
		}
		for _, className := range addClasses {
			newClasses[className] = api.NewNotificationClass(className)
		}
		for _, className := range removeClasses {
			delete(newClasses, className)
		}

		finalClasses := make(api.NotificationClasses, 0, len(newClasses))
		for _, nc := range newClasses {
			finalClasses = append(finalClasses, nc)
		}

		newTags := make(map[api.Tag]bool)
		for _, t := range currentNotification.Tags {
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

		req := SSHNotificationUpdateRequest{
			ManagementCode: managementCode,
			NotificationUpdateRequest: api.NotificationUpdateRequest{
				Classes: &finalClasses,
				Tags:    &finalTags,
			},
		}
		return doSSH(ssh, api.SSHRequestNotificationUpdate, &req)
	}

	mytoken := notificationsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	// First, get current notification state
	listRes, err := mtServer.Notifications.APIList(mytoken)
	if err != nil {
		return err
	}

	var currentNotification *api.NotificationInfo
	for _, n := range listRes.Notifications {
		if n.ManagementCode == managementCode {
			currentNotification = &n
			break
		}
	}
	if currentNotification == nil {
		return fmt.Errorf("notification with management code '%s' not found", managementCode)
	}

	// Build new classes list
	newClasses := make(map[string]*api.NotificationClass)
	for _, c := range currentNotification.Classes {
		newClasses[c.Name] = c
	}

	// Add classes
	for _, className := range addClasses {
		newClasses[className] = api.NewNotificationClass(className)
	}

	// Remove classes
	for _, className := range removeClasses {
		delete(newClasses, className)
	}

	// Convert map back to slice
	finalClasses := make(api.NotificationClasses, 0, len(newClasses))
	for _, nc := range newClasses {
		finalClasses = append(finalClasses, nc)
	}

	// Build new tags list
	newTags := make(map[api.Tag]bool)
	for _, t := range currentNotification.Tags {
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

	req := api.NotificationUpdateRequest{
		Classes: &finalClasses,
		Tags:    &finalTags,
	}

	res, err := mtServer.Notifications.APIUpdate(mytoken, managementCode, req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Notification '%s' updated successfully\n", managementCode)
	return nil
}

func deleteNotification(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("management-code is required")
	}
	managementCode := cmd.Args().Get(0)

	if !notificationsOptions.Force {
		prompt := fmt.Sprintf("Are you sure you want to delete notification %s?", managementCode)
		if !prompter.YN(prompt, false) {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	if ssh := notificationsOptions.SSH(); ssh != "" {
		req := SSHNotificationManagementCodeRequest{ManagementCode: managementCode}
		return doSSH(ssh, api.SSHRequestNotificationDelete, &req)
	}

	mytoken := notificationsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	res, err := mtServer.Notifications.APIDelete(mytoken, managementCode)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Notification '%s' deleted successfully\n", managementCode)
	return nil
}

func addTokenToNotification(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("management-code is required")
	}
	managementCode := cmd.Args().Get(0)

	if ssh := notificationsOptions.SSH(); ssh != "" {
		req := SSHNotificationAddTokenRequest{
			ManagementCode: managementCode,
			NotificationAddTokenRequest: api.NotificationAddTokenRequest{
				MOMID:           notificationsOptions.MOMID,
				IncludeChildren: notificationsOptions.IncludeChildren,
			},
		}
		return doSSH(ssh, api.SSHRequestNotificationAddToken, &req)
	}

	mytoken := notificationsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	req := api.NotificationAddTokenRequest{
		Mytoken:         mytoken,
		MOMID:           notificationsOptions.MOMID,
		IncludeChildren: notificationsOptions.IncludeChildren,
	}

	res, err := mtServer.Notifications.APIAddToken(mytoken, managementCode, req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Token added to notification '%s' successfully\n", managementCode)
	return nil
}

func removeTokenFromNotification(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("management-code is required")
	}
	managementCode := cmd.Args().Get(0)

	if ssh := notificationsOptions.SSH(); ssh != "" {
		type request struct {
			ManagementCode string `json:"management_code"`
			MOMID          string `json:"mom_id"`
		}
		return doSSH(
			ssh, api.SSHRequestNotificationRemoveToken, &request{
				ManagementCode: managementCode,
				MOMID:          notificationsOptions.MOMID,
			},
		)
	}

	mytoken := notificationsOptions.MustGetToken()
	mtServer := config.Get().Mytoken()

	req := api.NotificationRemoveTokenRequest{
		Mytoken: mytoken,
		MOMID:   notificationsOptions.MOMID,
	}

	res, err := mtServer.Notifications.APIRemoveToken(mytoken, managementCode, req)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}

	fmt.Printf("Token removed from notification '%s' successfully\n", managementCode)
	return nil
}
