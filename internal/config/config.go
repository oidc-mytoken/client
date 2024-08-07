package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/oidc-mytoken/api/v0"
	mytokenlib "github.com/oidc-mytoken/lib"
	"github.com/oidc-mytoken/utils/httpclient"
	"github.com/oidc-mytoken/utils/utils/fileutil"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	URL     string                    `yaml:"instance"`
	mytoken *mytokenlib.MytokenServer `yaml:"-"`

	DefaultProvider          string            `yaml:"default_provider"`
	DefaultTokenCapabilities []string          `yaml:"default_token_capabilities"`
	TokenNamePrefix          string            `yaml:"token_name_prefix"`
	UseWLCGTokenDiscovery    bool              `yaml:"use_wlcg_token_discovery"`
	Providers                map[string]string `yaml:"providers"`

	usedConfigDir string
	Hostname      string
}

var defaultConfig = Config{
	DefaultTokenCapabilities: api.Capabilities{
		api.CapabilityAT,
		api.CapabilityTokeninfo,
	}.Strings(),
	TokenNamePrefix:       "<hostname>",
	UseWLCGTokenDiscovery: true,
	URL:                   "https://mytoken.data.kit.edu",
}

var conf *Config

// Get returns the config
func Get() *Config {
	return conf
}

func (c *Config) Mytoken() *mytokenlib.MytokenServer {
	if c.mytoken != nil {
		return c.mytoken
	}
	mytoken, err := mytokenlib.NewMytokenServer(conf.URL)
	if err != nil {
		log.Fatal(errors.Wrap(err, "could not initialize mytoken server"))
	}
	conf.mytoken = mytoken
	return mytoken
}

func (c *Config) SetMytokenServer(mytoken *mytokenlib.MytokenServer) {
	c.mytoken = mytoken
}

func load(name string, locations []string) {
	data, usedLocation, err := fileutil.ReadConfigFile(name, locations)
	if err != nil {
		log.WithError(err).Warning()
	}
	conf = &defaultConfig
	if err = yaml.Unmarshal(data, conf); err != nil {
		log.Fatal(err)
	}
	conf.usedConfigDir = usedLocation
	mytokenlib.SetClient(httpclient.Do().GetClient())

	hostname, _ := os.Hostname()
	conf.Hostname = hostname
	conf.TokenNamePrefix = strings.ReplaceAll(conf.TokenNamePrefix, "<hostname>", hostname)
}

// LoadDefault loads the config from one of the default config locations
func LoadDefault() {
	load("config.yaml", possibleConfigLocations)
}

// Load loads the config form the provided filepath
func Load(file string) { // skipcq RVV-B0001
	filename := filepath.Base(file)
	path := filepath.Dir(file)
	load(filename, []string{path})
}

var possibleConfigLocations = []string{
	"~/.config/mytoken",
	"~/.mytoken",
}
