package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/oidc-mytoken/server/shared/httpClient"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/oidc-mytoken/server/shared/utils/fileutil"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/oidc-mytoken/client/internal/model"
	"github.com/oidc-mytoken/client/internal/utils/cryptutils"
)

type Config struct {
	URL     string                    `yaml:"instance"`
	Mytoken *mytokenlib.MytokenServer `yaml:"-"`

	DefaultGPGKey            string `yaml:"default_gpg_key"`
	DefaultProvider          string `yaml:"default_provider"`
	DefaultOIDCFlow          string `yaml:"default_oidc_flow"`
	DefaultTokenCapabilities struct {
		Stored   []string `yaml:"stored"`
		Returned []string `yaml:"returned"`
	} `yaml:"default_token_capabilities"`

	TokenNamePrefix string `yaml:"token_name_prefix"`

	Providers         model.Providers   `yaml:"providers"`
	TokensFilePath    string            `yaml:"tokens_file"`
	TokensFileContent *TokenFileContent `yaml:"-"`

	usedConfigDir string
}

type TokenFileContent struct {
	TokenMapping tokenNameMapping `json:"mapping"`
	Tokens       tokenEntries     `json:"tokens"`
}

type tokenNameMapping map[string][]string

type tokenEntries map[string][]TokenEntry

func (f TokenFileContent) Has(name, iss string) bool {
	return f.Tokens.Has(name, iss)
}
func (e tokenEntries) Has(name, iss string) bool {
	for _, tt := range e[iss] {
		if tt.Name == name {
			return true
		}
	}
	return false
}

func (f *TokenFileContent) Add(t TokenEntry, iss string) {
	f.Tokens.add(t, iss, false)
	f.TokenMapping.add(t, iss)
}

func (f *TokenFileContent) Update(name, iss, token string) {
	t := TokenEntry{
		Name:  name,
		Token: token,
	}
	f.Tokens.add(t, iss, true)
	f.TokenMapping.add(t, iss)
}

func (e *tokenEntries) add(t TokenEntry, iss string, update bool) {
	for i, tt := range (*e)[iss] {
		if tt.Name == t.Name {
			if t.GPGKey != "" || !update {
				tt.GPGKey = t.GPGKey
			}
			tt.Token = t.Token
			(*e)[iss][i] = tt
			return
		}
	}
	(*e)[iss] = append((*e)[iss], t)
}
func (m *tokenNameMapping) add(t TokenEntry, iss string) {
	if utils.StringInSlice(iss, (*m)[t.Name]) {
		return
	}
	(*m)[t.Name] = append((*m)[t.Name], iss)
}

func (f *TokenFileContent) Remove(name, iss string) {
	f.Tokens.remove(name, iss)
	f.TokenMapping.remove(name, iss)
}
func (e *tokenEntries) remove(name, iss string) {
	entries := (*e)[iss]
	if len(entries) == 1 {
		if entries[0].Name != name {
			return
		}
		delete(*e, iss)
		return
	}
	for i, tt := range entries {
		if tt.Name == name {
			entries = append(entries[:i], entries[i+1:]...)
			(*e)[iss] = entries
			return
		}
	}
}
func (m *tokenNameMapping) remove(name, iss string) {
	issuers := (*m)[name]
	if !utils.StringInSlice(iss, issuers) {
		return
	}
	if len(issuers) == 1 {
		delete(*m, name)
		return
	}
	for i, el := range issuers {
		if el == iss {
			issuers = append(issuers[:i], issuers[i+1:]...)
			break
		}
	}
	(*m)[name] = issuers
}

type TokenEntry struct {
	Name   string `json:"name"`
	GPGKey string `json:"gpg_key,omitempty"`
	Token  string `json:"token"`
}

func (c *Config) GetToken(issuer string, name *string) (string, error) {
	tt, found := c.TokensFileContent.Tokens[issuer]
	if !found {
		return "", fmt.Errorf("No tokens found for provider '%s'", issuer)
	}
	if *name == "" {
		p, _ := c.Providers.FindBy(issuer, true)
		*name = p.DefaultToken
		if *name == "" {
			if len(tt) == 1 {
				*name = tt[0].Name
			}
		}
	}
	for _, t := range tt {
		if t.Name == *name {
			var token string
			var err error
			if t.GPGKey != "" {
				token, err = cryptutils.DecryptGPG(t.Token, t.GPGKey)
			} else {
				token, err = cryptutils.DecryptPassword(t.Token)
			}
			if err != nil {
				err = fmt.Errorf("Failed to decrypt token named '%s' for '%s'", name, issuer)
			}
			return token, err
		}
	}
	return "", fmt.Errorf("Token name '%s' not found for '%s'", name, issuer)
}

var defaultConfig = Config{
	DefaultOIDCFlow: "auth",
	DefaultTokenCapabilities: struct {
		Stored   []string `yaml:"stored"`
		Returned []string `yaml:"returned"`
	}{
		Stored:   api.Capabilities{api.CapabilityAT, api.CapabilityCreateMT, api.CapabilityTokeninfo}.Strings(),
		Returned: api.Capabilities{api.CapabilityAT}.Strings(),
	},
	TokenNamePrefix: "<hostname>",
	TokensFilePath:  "tokens.json",
}

var conf *Config

// Get returns the config
func Get() *Config {
	return conf
}

func getTokensFilePath() string {
	filename := conf.TokensFilePath
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(conf.usedConfigDir, filename)
}

func (f *TokenFileContent) Save() error {
	data, err := json.MarshalIndent(*f, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(getTokensFilePath(), data, 0600)
}

func LoadTokens() (*TokenFileContent, error) {
	f := TokenFileContent{
		TokenMapping: tokenNameMapping{},
		Tokens:       tokenEntries{},
	}
	data, err := ioutil.ReadFile(getTokensFilePath())
	if err != nil || len(data) == 0 {
		return &f, nil
	}
	err = json.Unmarshal(data, &f)
	return &f, err
}

func load(name string, locations []string) {
	data, usedLocation := fileutil.ReadConfigFile(name, locations)
	conf = &defaultConfig
	if err := yaml.Unmarshal(data, conf); err != nil {
		log.Fatal(err)
	}
	conf.usedConfigDir = usedLocation
	if conf.URL == "" {
		log.Fatal("Must provide url of the mytoken instance in the config file.")
	}
	mytokenlib.SetClient(httpClient.Do().GetClient())
	mytoken, err := mytokenlib.NewMytokenServer(conf.URL)
	if err != nil {
		log.Fatal(err)
	}
	conf.Mytoken = mytoken

	if conf.DefaultGPGKey != "" {
		for _, p := range conf.Providers {
			if p.GPGKey == "" {
				p.GPGKey = conf.DefaultGPGKey
			}
		}
	}
	conf.TokensFileContent, err = LoadTokens()
	if err != nil {
		log.Fatal(err)
	}
	hostname, _ := os.Hostname()
	conf.TokenNamePrefix = strings.ReplaceAll(conf.TokenNamePrefix, "<hostname>", hostname)
}

// LoadDefault loads the config from one of the default config locations
func LoadDefault() {
	load("config.yaml", possibleConfigLocations)
}

// Load loads the config form the provided filepath
func Load(file string) {
	filename := filepath.Base(file)
	path := filepath.Dir(file)
	load(filename, []string{path})
}

var possibleConfigLocations = []string{
	"~/.config/mytoken",
	"~/.mytoken",
}
