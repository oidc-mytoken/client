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

func (f *TokenFileContent) Update(name, iss string, token StoreToken) {
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
			if t.Capabilities != nil || !update {
				tt.Capabilities = t.Capabilities
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
	Name         string           `json:"name"`
	GPGKey       string           `json:"gpg_key,omitempty"`
	Token        StoreToken       `json:"token"`
	Capabilities api.Capabilities `json:"capabilities"`
}

func (e TokenEntry) MarshalJSON() ([]byte, error) {
	type tokenEntry2 TokenEntry
	if _, err := e.Token.Encrypted(e.GPGKey); err != nil {
		return nil, err
	}
	return json.Marshal(tokenEntry2(e))
}

type StoreToken struct {
	plain     string
	crypt     string
	cryptMode Crypter
}

type Crypter interface {
	Encrypt(plain, secret string) (cipher string, err error)
	Decrypt(cipher, secret string) (plain string, err error)
}

type GPGAndPasswordCombinedCrypter struct{}

func (GPGAndPasswordCombinedCrypter) Encrypt(plain, gpgKey string) (cipher string, err error) {
	if gpgKey != "" {
		return cryptutils.EncryptGPG(plain, gpgKey)
	}
	return cryptutils.EncryptPassword(plain)
}
func (GPGAndPasswordCombinedCrypter) Decrypt(cipher, gpgKey string) (plain string, err error) {
	if gpgKey != "" {
		return cryptutils.DecryptGPG(cipher, gpgKey)
	}
	return cryptutils.DecryptPassword(cipher)
}

func (t *StoreToken) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	(*t).crypt = str
	(*t).cryptMode = GPGAndPasswordCombinedCrypter{}
	return nil
}
func (t StoreToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.crypt)
}

func (t *StoreToken) Plain(secret string) (string, error) {
	var err error
	if t.plain == "" {
		t.plain, err = t.cryptMode.Decrypt(t.crypt, secret)
	}
	return t.plain, err
}

func (t *StoreToken) Encrypted(secret string) (string, error) {
	var err error
	if t.crypt == "" {
		t.crypt, err = t.cryptMode.Encrypt(t.plain, secret)
	}
	return t.crypt, err
}

func NewPlainStoreToken(plain string) StoreToken {
	return StoreToken{
		plain:     plain,
		cryptMode: GPGAndPasswordCombinedCrypter{},
	}
}

func NewEncryptedStoreToken(encrypted string) StoreToken {
	return StoreToken{
		crypt:     encrypted,
		cryptMode: GPGAndPasswordCombinedCrypter{},
	}
}

func (c *Config) GetToken(issuer string, nameGet func() string, nameUpdater func(string),
	requiredCapability ...api.Capability) (
	string,
	error) {
	entry, err := c.GetTokenEntry(issuer, nameGet(), nameUpdater, requiredCapability...)
	if err != nil {
		return "", err
	}
	token, err := entry.Token.Plain(entry.GPGKey)
	if err != nil {
		err = fmt.Errorf("Failed to decrypt token named '%s' for '%s'", nameGet(), issuer)
	}
	return token, err
}

func (c *Config) GetTokenEntry(issuer string, name string, nameUpdater func(string), requiredCapability ...api.
	Capability) (
	t TokenEntry,
	err error) {
	tt, found := c.TokensFileContent.Tokens[issuer]
	if !found {
		err = fmt.Errorf("No tokens found for provider '%s'", issuer)
		return
	}
	if name == "" {
		p, _ := c.Providers.FindBy(issuer, true)
		if len(requiredCapability) > 0 {
			var tokenIndexWithCapability *int
			for i, ttt := range tt {
				if ttt.Capabilities.Has(requiredCapability[0]) {
					if tokenIndexWithCapability == nil {
						tokenIndexWithCapability = utils.NewInt(i)
					} else { // We have more than one token with the correct capability,
						// break because we don't know which one to use
						tokenIndexWithCapability = nil
						break
					}
				}
			}
			if tokenIndexWithCapability != nil {
				nameUpdater(tt[*tokenIndexWithCapability].Name)
				t = tt[*tokenIndexWithCapability]
				return
			}
		}
		nameUpdater(p.DefaultToken)
		if name == "" {
			if len(tt) == 1 {
				nameUpdater(tt[0].Name)
				t = tt[0]
				return
			}
		}
	}
	for _, t = range tt {
		if t.Name == name /*&& (len(requiredCapability) == 0 || t.Capabilities.Has(requiredCapability[0]))*/ {
			return
		}
	}
	err = fmt.Errorf("Token name '%s' not found for '%s'", name, issuer)
	return
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
