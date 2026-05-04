package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/oidc-mytoken/client/internal/config"
)

func init() {
	// Config command
	configCmd := &cli.Command{
		Name:   "config",
		Usage:  "Get server configuration",
		Action: getConfig,
	}
	app.Commands = append(app.Commands, configCmd)

	// Capabilities command
	capabilitiesCmd := &cli.Command{
		Name:   "capabilities",
		Usage:  "List available capability templates",
		Action: getCapabilities,
	}
	app.Commands = append(app.Commands, capabilitiesCmd)
}

func getConfig(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()
	serverConfig := mtServer.ServerMetadata

	data, err := json.MarshalIndent(serverConfig, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

type CapabilityEntry struct {
	ReadWriteCapability CapabilityInfo    `json:"read_write_capability"`
	ReadOnlyCapability  *CapabilityInfo   `json:"read_only_capability,omitempty"`
	Children            []CapabilityEntry `json:"children,omitempty"`
}

type CapabilityInfo struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	IsReadOnly      *bool  `json:"is_read_only,omitempty"`
	ColorClass      string `json:"color_class,omitempty"`
	CapabilityLevel string `json:"capability_level,omitempty"`
}

func getCapabilities(_ context.Context, _ *cli.Command) error {
	mtServer := config.Get().Mytoken()

	// Construct capabilities endpoint URL from server metadata
	baseURL := mtServer.ServerMetadata.Issuer
	var capsURL string
	if baseURL[len(baseURL)-1] == '/' {
		capsURL = baseURL + "api/v0/capabilities"
	} else {
		capsURL = baseURL + "/api/v0/capabilities"
	}

	// Make HTTP request to capabilities endpoint
	req, err := http.NewRequest("GET", capsURL, nil)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch capabilities: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var capabilities []CapabilityEntry
	if err := json.Unmarshal(body, &capabilities); err != nil {
		return fmt.Errorf("failed to decode capabilities: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION")
	fmt.Fprintln(w, "----\t-----------")

	printCapabilityTree(w, capabilities, "")

	w.Flush()
	return nil
}

func printCapabilityTree(w *tabwriter.Writer, capabilities []CapabilityEntry, indent string) {
	for _, capEntry := range capabilities {
		name := capEntry.ReadWriteCapability.Name
		desc := capEntry.ReadWriteCapability.Description

		// Print read-write capability
		fmt.Fprintf(w, "%s%s\t%s\n", indent, name, desc)

		// Print read-only capability if exists
		if capEntry.ReadOnlyCapability != nil {
			fmt.Fprintf(w, "%sread@%s\t%s\n", indent, name, capEntry.ReadOnlyCapability.Description)
		}

		// Print children if any
		if len(capEntry.Children) > 0 {
			printCapabilityTree(w, capEntry.Children, indent+"  ")
		}
	}
}
