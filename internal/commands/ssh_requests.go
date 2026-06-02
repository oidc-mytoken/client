package commands

import "github.com/oidc-mytoken/api/v0"

// SSHCalendarUpdateRequest is the request body for updating a calendar via SSH
type SSHCalendarUpdateRequest struct {
	CalendarID string `json:"calendar_id"`
	api.CreateCalendarRequest
}

// SSHCalendarIDRequest is used for calendar operations that only need the calendar ID
type SSHCalendarIDRequest struct {
	CalendarID string `json:"calendar_id"`
}

// SSHCalendarSubscriptionRequest is used for subscribing/unsubscribing to calendars
type SSHCalendarSubscriptionRequest struct {
	CalendarID string `json:"calendar_id"`
	api.AddMytokenToCalendarRequest
}

// SSHNotificationUpdateRequest is the request body for updating a notification via SSH
type SSHNotificationUpdateRequest struct {
	ManagementCode string `json:"management_code"`
	api.NotificationUpdateRequest
}

// SSHNotificationManagementCodeRequest is used for notification operations that only need the management code
type SSHNotificationManagementCodeRequest struct {
	ManagementCode string `json:"management_code"`
}

// SSHNotificationAddTokenRequest is used for adding a token to a notification via SSH
type SSHNotificationAddTokenRequest struct {
	ManagementCode string `json:"management_code"`
	api.NotificationAddTokenRequest
}

// SSHTagCreateRequest is the request body for creating a tag via SSH
type SSHTagCreateRequest struct {
	Tag   api.Tag `json:"tag"`
	Color *string `json:"color,omitempty"`
}

// SSHTagUpdateRequest is the request body for updating a tag via SSH
type SSHTagUpdateRequest struct {
	Tag   api.Tag `json:"tag"`
	Color *string `json:"color,omitempty"`
	Name  *string `json:"name,omitempty"`
}

// SSHTagDeleteRequest is used for deleting a tag
type SSHTagDeleteRequest struct {
	Tag api.Tag `json:"tag"`
}
