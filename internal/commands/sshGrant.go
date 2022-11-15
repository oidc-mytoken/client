package commands

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/oidc-mytoken/utils/utils/fileutil"
	"github.com/oidc-mytoken/utils/utils/profile"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/oidc-mytoken/client/internal/config"
	"github.com/oidc-mytoken/client/internal/utils/tablewriter"
)

var noWriteHostEntry bool
var optName string
var optCapabilities string
var optRestrictions restrictionOpts

func initSSHGrant(parent *cli.Command) {
	cmdFlags := getMTFlags()
	subCmdFlags := getMTFlags()
	cmd := &cli.Command{
		Name:    "ssh",
		Aliases: []string{"SSH"},
		Usage:   "View and manage the ssh grant",
		Flags:   cmdFlags,
		Subcommands: []*cli.Command{
			{
				Name:    "list",
				Aliases: []string{"view"},
				Usage:   "Lists your ssh keys",
				Action:  listSSH,
				Flags:   subCmdFlags,
			},
			{
				Name:      "add",
				Aliases:   []string{"new"},
				ArgsUsage: "SSH_KEY",
				Usage: "Adds a new ssh key. You can pass the whole public key, " +
					"or a filepath to the public key (recommended)",
				Action: addSSHKey,
				Flags: append(
					append(
						getRestrFlags(&optRestrictions),
						getCapabilityFlag(&optCapabilities),
						&cli.StringFlag{
							Name:        "key-name",
							Usage:       "A name for identifying this ssh key",
							Destination: &optName,
						},
						&cli.BoolFlag{
							Name: "no-write-host-entry",
							Usage: "If set, " +
								"the created host entry will not be automatically append to your ~/.ssh/config file.",
							EnvVars:     []string{"NO_WRITE_HOST_ENTRY"},
							Destination: &noWriteHostEntry,
						},
					),
					subCmdFlags...,
				),
			},
			{
				Name:      "delete",
				Aliases:   []string{"remove"},
				ArgsUsage: "SSH_KEY",
				Usage: "Removes an ssh key. You can pass the SHA256 fingerprint (recommended), " +
					"the whole public key, or a filepath to the public key.",
				Action: deleteSSHKey,
				Flags:  subCmdFlags,
			},
		},
	}
	parent.Subcommands = append(parent.Subcommands, cmd)
}

func listSSH(_ *cli.Context) error {
	mytoken := settingsOptions.MustGetToken()
	res, err := config.Get().Mytoken.UserSettings.Grants.SSH.APIGet(mytoken)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}
	if res.GrantEnabled {
		fmt.Println("SSH Grant Type is enabled.")
	} else {
		fmt.Println("SSH Grant Type is not enabled.")
	}
	outputData := make([]tablewriter.TableWriter, len(res.SSHKeyInfo))
	for i, d := range res.SSHKeyInfo {
		outputData[i] = tableSSHKeyInfo(d)
	}
	tablewriter.PrintTableData(outputData)
	return nil
}

type tableSSHKeyInfo api.SSHKeyInfo

func (tableSSHKeyInfo) TableGetHeader() []string {
	return []string{
		"Name",
		"SSH Key Fingerprint",
		"Created",
		"Last Used",
	}
}

func (i tableSSHKeyInfo) TableGetRow() []string {
	const timeFmt = "2006-01-02 15:04:05"
	lastUsed := ""
	if i.LastUsed != nil {
		lastUsed = time.Unix(*i.LastUsed, 0).Format(timeFmt)
	}
	return []string{
		i.Name,
		i.SSHKeyFingerprint,
		time.Unix(i.Created, 0).Format(timeFmt),
		lastUsed,
	}
}

func addSSHKey(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		if ctx.NArg() > 1 {
			return fmt.Errorf("Need exactly one argument")
		}
		return fmt.Errorf("Required argument SSH_KEY missing")
	}
	keyArg := ctx.Args().Get(0)
	mytoken := settingsOptions.MustGetToken()
	key, err := detectKey(keyArg)
	if err != nil {
		return err
	}
	callbacks := mytokenlib.PollingCallbacks{
		Init: func(authorizationURL string) error {
			fmt.Fprintln(os.Stderr, "Using any device please visit the following url to continue:")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, authorizationURL)
			fmt.Fprintln(os.Stderr)
			return nil
		},
		Callback: func(interval int64, iteration int) {
			if iteration == 0 {
				fmt.Fprint(os.Stderr, "Starting polling ...")
				return
			}
			if int64(iteration)%(15/interval) == 0 { // every 15s
				fmt.Fprint(os.Stderr, ".")
			}
		},
		End: func() {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "success")
		},
	}
	caps, err := profile.ParseCapabilityTemplate([]byte(optCapabilities))
	if err != nil {
		return err
	}
	restrictions, err := parseRestrictionOpts(optRestrictions, ctx)
	if err != nil {
		return err
	}
	res, tokenUpdate, err := config.Get().Mytoken.UserSettings.Grants.SSH.APIAdd(
		mytoken, key, optName, restrictions,
		caps, callbacks,
	)
	if tokenUpdate != nil {
		updateMytoken(tokenUpdate.Mytoken)
	}
	if err != nil {
		return err
	}
	fmt.Println("Successfully added ssh key")
	fmt.Printf("Please use the following username for ssh: '%s'\n", res.SSHUser)
	if res.SSHHostConfig != "" {
		if noWriteHostEntry {
			fmt.Printf(
				"You might want to add the following host entry to your ssh config file:\n\n%s\n", res.SSHHostConfig,
			)
		} else {
			const sshConfigFile = "~/.ssh/config"
			if err = fileutil.Append(sshConfigFile, "\n"+res.SSHHostConfig+"\n"); err != nil {
				return errors.Wrap(err, "error while writing ssh config")
			}
			fmt.Printf(
				"We added a host entry to your '%s' file. You can check and adapt it if necessary.\n",
				sshConfigFile,
			)
		}
	}
	return nil
}

func deleteSSHKey(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		if ctx.NArg() > 1 {
			return fmt.Errorf("Need exactly one argument")
		}
		return fmt.Errorf("Required argument SSH_KEY missing")
	}
	keyArg := ctx.Args().Get(0)
	mytoken := settingsOptions.MustGetToken()
	var keyFP string
	var key string
	if isKeyFP(keyArg) {
		keyFP = keyArg
	} else {
		var err error
		key, err = detectKey(keyArg)
		if err != nil {
			return err
		}
	}
	res, err := config.Get().Mytoken.UserSettings.Grants.SSH.APIRemove(mytoken, keyFP, key)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		updateMytoken(res.TokenUpdate.Mytoken)
	}
	fmt.Println("Successfully removed ssh key")
	return nil
}

func detectKey(str string) (string, error) {
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(str)); err == nil {
		return str, nil
	}
	// The passed string is not a valid ssh public key, we assume it is a filepath
	fileContent, err := os.ReadFile(str)
	if err != nil {
		return "", errors.Wrap(err, "could not detect ssh public key")
	}
	if _, _, _, _, err = ssh.ParseAuthorizedKey(fileContent); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("could not parse ssh key in file '%s'", str))
	}
	return string(fileContent), nil
}

func isKeyFP(str string) bool {
	return strings.HasPrefix(str, "SHA256:")
}
