package profile

import (
	"bytes"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/oidc-mytoken/api/v0"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/oidc-mytoken/server/shared/utils/unixtime"
)

var profileTemplateDummyData = map[string]string{
	"/etc/mytoken/profiles.d/A": `{
			"name": "test_profile_A",
			"rotation": "@A",
			"capabilities": ["AT", "@basic"],
			"restrictions": "example"
		}`,
	"~/.config/mytoken/profiles.d/B": `{
			"name": "test_profile_B",
			"rotation": {
				"include": ["1d", "revoke"],
				"on_AT": true
			},
			"capabilities": "AT @basic",
			"restrictions": [{
				"scope": "openid profile",
				"include": ["1d"]
			}, 
			"example",
			{
				"include": "1d ip-this"
			}]
		}`,
	"/etc/mytoken/profiles.d/nested":   `{"include":["A","nested-B"]}`,
	"/etc/mytoken/profiles.d/nested-B": `B`,

	"/etc/mytoken/rotation.d/A": `{
		"include":["1d"],
		"on_other": true
	}`,
	"/etc/mytoken/rotation.d/1d":          `{"lifetime":86400}`,
	"/etc/mytoken/rotation.d/1h":          `{"lifetime":3600}`,
	"/etc/mytoken/rotation.d/revoke":      `{"auto_revoke":true}`,
	"~/.config/mytoken/rotation.d/revoke": `{"auto_revoke":false}`,

	"~/.config/mytoken/capabilities.d/basic": `["AT", "tokeninfo", "list_mytokens"]`,

	"/etc/mytoken/restrictions.d/example": `[{
		"scope": "openid profile email eduperson_entitlement storage.read",
		"audience": ["https://storage.example.com"],
		"usages_AT": 1,
		"usages_other": 0
	}, {
		"scope": "openid profile email eduperson_entitlement compute",
		"audience": ["https://hpc.example.com"],
		"usages_AT": 1,
		"usages_other": 0
	}]`,
	"/etc/mytoken/restrictions.d/ip-this": `{"ip":["this"]}`,
	"/etc/mytoken/restrictions.d/1d":      `{"exp":"+1d"}`,
	"/etc/mytoken/restrictions.d/G":       `{"exp":"+1d","nbf":"+1h"}`,
	"~/.config/mytoken/restrictions.d/G":  `{"exp":"+2d","usages_AT":1}`,
}

func TestMain(m *testing.M) {
	templateReader = newTemplateReader(readDummyData)
	templateReader.userBaseDir = "~/.config/mytoken"
	os.Exit(m.Run())
}

func readDummyData(path string) ([]byte, error) {
	return []byte(profileTemplateDummyData[path]), nil
}

func TestTemplateReader_ReadFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "read non-existing",
			path:    "does-not-exist",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "read global",
			path:    "restrictions.d/1d",
			want:    []byte(profileTemplateDummyData["/etc/mytoken/restrictions.d/1d"]),
			wantErr: false,
		},
		{
			name:    "read user",
			path:    "capabilities.d/basic",
			want:    []byte(profileTemplateDummyData["~/.config/mytoken/capabilities.d/basic"]),
			wantErr: false,
		},
		{
			name:    "read both, user overwrites",
			path:    "rotation.d/revoke",
			want:    []byte(profileTemplateDummyData["~/.config/mytoken/rotation.d/revoke"]),
			wantErr: false,
		},
		{
			name:    "read both, combine",
			path:    "restrictions.d/G",
			want:    []byte(`{"exp":"+2d","nbf":"+1h","usages_AT":1}`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := templateReader.ReadFile(tt.path)
				if (err != nil) != tt.wantErr {
					t.Errorf("ReadFile() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !bytes.Equal(got, tt.want) {
					t.Errorf("ReadFile() got = '%s', want '%s'", got, tt.want)
				}
			},
		)
	}
}

func TestTemplateReader_readCapabilityTemplate(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "read non-existing",
			path:    "does-not-exist",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "read",
			path:    "basic",
			want:    []byte(profileTemplateDummyData["~/.config/mytoken/capabilities.d/basic"]),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := templateReader.readCapabilityTemplate(tt.path)
				if (err != nil) != tt.wantErr {
					t.Errorf("readCapabilityTemplate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !bytes.Equal(got, tt.want) {
					t.Errorf("readCapabilityTemplate() got = '%s', want '%s'", got, tt.want)
				}
			},
		)
	}
}

func TestTemplateReader_readProfile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "read non-existing",
			path:    "does-not-exist",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "read",
			path:    "A",
			want:    []byte(profileTemplateDummyData["/etc/mytoken/profiles.d/A"]),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := templateReader.readProfile(tt.path)
				if (err != nil) != tt.wantErr {
					t.Errorf("readProfile() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !bytes.Equal(got, tt.want) {
					t.Errorf("readProfile() got = '%s', want '%s'", got, tt.want)
				}
			},
		)
	}
}

func TestTemplateReader_readRestrictionsTemplate(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "read non-existing",
			path:    "does-not-exist",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "read",
			path:    "example",
			want:    []byte(profileTemplateDummyData["/etc/mytoken/restrictions.d/example"]),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := templateReader.readRestrictionsTemplate(tt.path)
				if (err != nil) != tt.wantErr {
					t.Errorf("readRestrictionsTemplate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !bytes.Equal(got, tt.want) {
					t.Errorf("readRestrictionsTemplate() got = '%s', want '%s'", got, tt.want)
				}
			},
		)
	}
}

func TestTemplateReader_readRotationTemplate(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "read non-existing",
			path:    "does-not-exist",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "read",
			path:    "revoke",
			want:    []byte(profileTemplateDummyData["~/.config/mytoken/rotation.d/revoke"]),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := templateReader.readRotationTemplate(tt.path)
				if (err != nil) != tt.wantErr {
					t.Errorf("readRotationTemplate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !bytes.Equal(got, tt.want) {
					t.Errorf("readRotationTemplate() got = '%s', want '%s'", got, tt.want)
				}
			},
		)
	}
}

func Test__parseCapabilityTemplate(t *testing.T) {
	tests := []struct {
		name           string
		content        []byte
		wantCapStrings []string
		wantErr        bool
	}{
		{
			name:           "nil",
			content:        nil,
			wantCapStrings: nil,
			wantErr:        false,
		},
		{
			name:           "empty",
			content:        []byte{},
			wantCapStrings: nil,
			wantErr:        false,
		},
		{
			name:    "string",
			content: []byte("AT other"),
			wantCapStrings: []string{
				"AT",
				"other",
			},
			wantErr: false,
		},
		{
			name:    "array",
			content: []byte(`["AT","other"]`),
			wantCapStrings: []string{
				"AT",
				"other",
			},
			wantErr: false,
		},
		{
			name:    "include in array",
			content: []byte(`["@basic"]`),
			wantCapStrings: []string{
				"AT",
				"tokeninfo",
				"list_mytokens",
			},
			wantErr: false,
		},
		{
			name:    "include as string",
			content: []byte("@basic"),
			wantCapStrings: []string{
				"AT",
				"tokeninfo",
				"list_mytokens",
			},
			wantErr: false,
		},
		{
			name:    "include in string with other",
			content: []byte("@basic other"),
			wantCapStrings: []string{
				"AT",
				"tokeninfo",
				"list_mytokens",
				"other",
			},
			wantErr: false,
		},
		{
			name:    "include in array with other",
			content: []byte(`["@basic", "other"]`),
			wantCapStrings: []string{
				"AT",
				"tokeninfo",
				"list_mytokens",
				"other",
			},
			wantErr: false,
		},
		{
			name:    "duplicates",
			content: []byte(`["other", "@basic", "other", "AT"]`),
			wantCapStrings: []string{
				"other",
				"AT",
				"tokeninfo",
				"list_mytokens",
				"other",
				"AT",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				gotCapStrings, err := _parseCapabilityTemplate(tt.content)
				if (err != nil) != tt.wantErr {
					t.Errorf("_parseCapabilityTemplate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(gotCapStrings, tt.wantCapStrings) {
					t.Errorf("_parseCapabilityTemplate() gotCapStrings = %v, want %v", gotCapStrings, tt.wantCapStrings)
				}
			},
		)
	}
}

func Test__parseCapabilityTemplateByName(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
	}{
		{
			name:     "non-existing",
			fullPath: "/etc/mytoken/capabilities.d/non-existing",
		},
		{
			name:     "basic",
			fullPath: "~/.config/mytoken/capabilities.d/basic",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				want, wantErr := _parseCapabilityTemplate([]byte(profileTemplateDummyData[tt.fullPath]))
				got, err := _parseCapabilityTemplateByName(tt.name)
				if err != nil && wantErr != nil && err.Error() != wantErr.Error() {
					t.Errorf("_parseCapabilityTemplateByName() error = %v, wantErr %v", err, wantErr)
					return
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("_parseCapabilityTemplateByName() got = %v, want %v", got, want)
				}
			},
		)
	}
}

func Test_normalizeTemplateName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "without @",
			in:   "example",
			want: "example",
		},
		{
			name: "with @",
			in:   "@example",
			want: "example",
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				if got := normalizeTemplateName(tt.in); got != tt.want {
					t.Errorf("normalizeTemplateName(\"%s\") = %v, want %v", tt.in, got, tt.want)
				}
			},
		)
	}
}

func Test_parseCapabilityTemplate(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    api.Capabilities
		wantErr bool
	}{
		{
			name:    "nil",
			content: nil,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "empty",
			content: []byte{},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "string",
			content: []byte("AT tokeninfo"),
			want: api.NewCapabilities(
				[]string{
					"AT",
					"tokeninfo",
				},
			),
			wantErr: false,
		},
		{
			name:    "string with non-existing cap",
			content: []byte("AT other"),
			want: api.NewCapabilities(
				[]string{
					"AT",
					"other",
				},
			),
			wantErr: false,
		},
		{
			name:    "array",
			content: []byte(`["AT","tokeninfo"]`),
			want: api.NewCapabilities(
				[]string{
					"AT",
					"tokeninfo",
				},
			),
			wantErr: false,
		},
		{
			name:    "include in array",
			content: []byte(`["@basic"]`),
			want: api.NewCapabilities(
				[]string{
					"AT",
					"tokeninfo",
					"list_mytokens",
				},
			),
			wantErr: false,
		},
		{
			name:    "include as string",
			content: []byte("@basic"),
			want: api.NewCapabilities(
				[]string{
					"AT",
					"tokeninfo",
					"list_mytokens",
				},
			),
			wantErr: false,
		},
		{
			name:    "include in string with other",
			content: []byte("@basic settings"),
			want: api.NewCapabilities(
				[]string{
					"AT",
					"tokeninfo",
					"list_mytokens",
					"settings",
				},
			),
			wantErr: false,
		},
		{
			name:    "include in array with other",
			content: []byte(`["@basic", "settings"]`),
			want: api.NewCapabilities(
				[]string{
					"AT",
					"tokeninfo",
					"list_mytokens",
					"settings",
				},
			),
			wantErr: false,
		},
		{
			name:    "duplicates",
			content: []byte(`["settings", "@basic", "settings", "AT"]`),
			want: api.NewCapabilities(
				[]string{
					"settings",
					"AT",
					"tokeninfo",
					"list_mytokens",
				},
			),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := ParseCapabilityTemplate(tt.content)
				if (err != nil) != tt.wantErr {
					t.Errorf("ParseCapabilityTemplate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("ParseCapabilityTemplate() got = %v, want %v", got, tt.want)
				}
			},
		)
	}
}

func Test_parseProfile(t *testing.T) {
	aProfile := api.GeneralMytokenRequest{
		Restrictions: exampleRestrictions,
		Capabilities: api.NewCapabilities(
			[]string{
				"AT",
				"tokeninfo",
				"list_mytokens",
			},
		),
		Name: "test_profile_A",
		Rotation: &api.Rotation{
			Lifetime: 86400,
			OnOther:  true,
		},
	}
	bProfile := api.GeneralMytokenRequest{
		Restrictions: api.Restrictions{
			{
				Scope:     "openid profile",
				ExpiresAt: int64(unixtime.InSeconds(86400)),
			},
			exampleRestrictions[0],
			exampleRestrictions[1],
			{
				ExpiresAt: int64(unixtime.InSeconds(86400)),
				IPs:       []string{"this"},
			},
		},
		Capabilities: api.NewCapabilities(
			[]string{
				"AT",
				"tokeninfo",
				"list_mytokens",
			},
		),
		Name: "test_profile_B",
		Rotation: &api.Rotation{
			Lifetime:   86400,
			OnAT:       true,
			AutoRevoke: false,
		},
	}
	bProfile2 := api.GeneralMytokenRequest{
		Issuer:       bProfile.Issuer,
		GrantType:    bProfile.GrantType,
		Restrictions: bProfile.Restrictions,
		Capabilities: bProfile.Capabilities,
		Name:         "changed",
		ResponseType: bProfile.ResponseType,
		MaxTokenLen:  bProfile.MaxTokenLen,
		Rotation:     bProfile.Rotation,
	}

	tests := []struct {
		name    string
		content []byte
		want    api.GeneralMytokenRequest
		wantErr bool
	}{
		{
			name:    "nil",
			content: nil,
			want:    api.GeneralMytokenRequest{},
			wantErr: false,
		},
		{
			name:    "empty",
			content: []byte{},
			want:    api.GeneralMytokenRequest{},
			wantErr: false,
		},
		{
			name:    "array",
			content: []byte(`[{"name":"test"}]`),
			want:    api.GeneralMytokenRequest{},
			wantErr: true,
		},
		{
			name:    "basics",
			content: []byte(`{"name":"test"}`),
			want:    api.GeneralMytokenRequest{Name: "test"},
			wantErr: false,
		},
		{
			name:    "single profile A",
			content: []byte(`A`),
			want:    aProfile,
			wantErr: false,
		},
		{
			name:    "single profile B",
			content: []byte(`B`),
			want:    bProfile,
			wantErr: false,
		},
		{
			name:    "adapted profile B",
			content: []byte(`{"include":["B"],"name":"changed"}`),
			want:    bProfile2,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := ParseProfile(tt.content)
				if (err != nil) != tt.wantErr {
					t.Errorf("ParseProfile() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("ParseProfile() got = %+v, want %+v", got, tt.want)
				}
			},
		)
	}
}

func Test_parseProfileByName(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
	}{
		{
			name:     "non-existing",
			fullPath: "/etc/mytoken/profiles.d/non-existing",
		},
		{
			name:     "A",
			fullPath: "/etc/mytoken/profiles.d/A",
		},
		{
			name:     "B",
			fullPath: "~/.config/mytoken/profiles.d/B",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				want, wantErr := ParseProfile([]byte(profileTemplateDummyData[tt.fullPath]))
				got, err := parseProfileByName(tt.name)
				if err != nil && wantErr != nil && err.Error() != wantErr.Error() {
					t.Errorf("parseProfileByName() error = %v, wantErr %v", err, wantErr)
					return
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("parseProfileByName() got = %v, want %v", got, want)
				}
			},
		)
	}
}

var exampleRestrictions = api.Restrictions{
	&api.Restriction{
		Scope:       "openid profile email eduperson_entitlement storage.read",
		Audiences:   []string{"https://storage.example.com"},
		UsagesAT:    utils.NewInt64(1),
		UsagesOther: utils.NewInt64(0),
	},
	&api.Restriction{
		Scope:       "openid profile email eduperson_entitlement compute",
		Audiences:   []string{"https://hpc.example.com"},
		UsagesAT:    utils.NewInt64(1),
		UsagesOther: utils.NewInt64(0),
	},
}

func Test_parseRestrictionsTemplate(t *testing.T) {

	tests := []struct {
		name    string
		content []byte
		want    api.Restrictions
		wantErr bool
	}{
		{
			name:    "nil",
			content: nil,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "empty",
			content: []byte{},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "object",
			content: []byte(`{"usages_AT":1}`),
			want:    api.Restrictions{&api.Restriction{UsagesAT: utils.NewInt64(1)}},
			wantErr: false,
		},
		{
			name:    "exp number",
			content: []byte(`{"exp":1}`),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "exp number string",
			content: []byte(`{"exp":"1"}`),
			want:    api.Restrictions{&api.Restriction{ExpiresAt: 1}},
			wantErr: false,
		},
		{
			name:    "exp 1d",
			content: []byte(`{"exp":"+1d"}`),
			want:    api.Restrictions{&api.Restriction{ExpiresAt: time.Now().Add(time.Hour * 24).Unix()}},
			wantErr: false,
		},
		{
			name:    "empty object",
			content: []byte(`{}`),
			want:    api.Restrictions{},
		},
		{
			name:    "empty array",
			content: []byte(`[]`),
			want:    api.Restrictions{},
			wantErr: false,
		},
		{
			name:    "array",
			content: []byte(`[{"usages_AT":1},{"scope":"openid profile"}]`),
			want: api.Restrictions{
				&api.Restriction{UsagesAT: utils.NewInt64(1)},
				&api.Restriction{Scope: "openid profile"},
			},
			wantErr: false,
		},
		{
			name:    "single template",
			content: []byte(`example`),
			want:    exampleRestrictions,
			wantErr: false,
		},
		{
			name:    "single include in object without @",
			content: []byte(`{"include":["example"]}`),
			want:    exampleRestrictions,
			wantErr: false,
		},
		{
			name:    "single include in object with @",
			content: []byte(`{"include":["@example"]}`),
			want:    exampleRestrictions,
			wantErr: false,
		},
		{
			name:    "single include in array",
			content: []byte(`[{"include":["@example"]}]`),
			want:    exampleRestrictions,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := ParseRestrictionsTemplate(tt.content)
				if (err != nil) != tt.wantErr {
					t.Errorf("ParseRestrictionsTemplate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("ParseRestrictionsTemplate() got = %+v, want %+v", got, tt.want)
				}
			},
		)
	}
}

func Test_parseRestrictionsTemplateByName(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "non-existing",
			content: profileTemplateDummyData["/etc/mytoken/restrictions.d/non-existing"],
		},
		{
			name:    "example",
			content: profileTemplateDummyData["/etc/mytoken/restrictions.d/example"],
		},
		{
			name:    "1d",
			content: profileTemplateDummyData["/etc/mytoken/restrictions.d/1d"],
		},
		{
			name:    "ip-this",
			content: profileTemplateDummyData["/etc/mytoken/restrictions.d/ip-this"],
		},
		{
			name:    "G",
			content: `{"exp":"+2d","nbf":"+1h","usages_AT":1}`,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				want, wantErr := ParseRestrictionsTemplate([]byte(tt.content))
				got, err := parseRestrictionsTemplateByName(tt.name)
				if err != nil && wantErr != nil && err.Error() != wantErr.Error() {
					t.Errorf("parseRestrictionsTemplateByName() error = %v, wantErr %v", err, wantErr)
					return
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("parseRestrictionsTemplateByName() got = %+v, want %+v", got, want)
				}
			},
		)
	}
}

func Test_parseRotationTemplate(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    *api.Rotation
		wantErr bool
	}{
		{
			name:    "nil",
			content: nil,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "empty",
			content: []byte{},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "object with single claim",
			content: []byte(`{"on_AT":true}`),
			want:    &api.Rotation{OnAT: true},
			wantErr: false,
		},
		{
			name:    "array",
			content: []byte(`[{"on_AT":true}]`),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "single template name",
			content: []byte(`1d`),
			want:    &api.Rotation{Lifetime: 86400},
			wantErr: false,
		},
		{
			name:    "single template name with @",
			content: []byte(`@1d`),
			want:    &api.Rotation{Lifetime: 86400},
			wantErr: false,
		},
		{
			name:    "overwrite order",
			content: []byte(`1d 1h`),
			want:    &api.Rotation{Lifetime: 86400},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := ParseRotationTemplate(tt.content)
				if (err != nil) != tt.wantErr {
					t.Errorf("ParseRotationTemplate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if err == nil && !reflect.DeepEqual(got, tt.want) {
					t.Errorf("ParseRotationTemplate() got = %v, want %v", got, tt.want)
				}
			},
		)
	}
}

func Test_parseRotationTemplateByName(t *testing.T) {
	tests := []struct {
		name     string
		fullPath string
	}{
		{
			name:     "non-existing",
			fullPath: "/etc/mytoken/rotation.d/non-existing",
		},
		{
			name:     "A",
			fullPath: "/etc/mytoken/rotation.d/A",
		},
		{
			name:     "1d",
			fullPath: "/etc/mytoken/rotation.d/1d",
		},
		{
			name:     "revoke",
			fullPath: "~/.config/mytoken/rotation.d/revoke",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				want, wantErr := ParseRotationTemplate([]byte(profileTemplateDummyData[tt.fullPath]))
				got, err := parseRotationTemplateByName(tt.name)
				if err != nil && wantErr != nil && err.Error() != wantErr.Error() {
					t.Errorf("parseRotationTemplateByName() error = %v, wantErr %v", err, wantErr)
					return
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("parseRotationTemplateByName() got = %v, want %v", got, want)
				}
			},
		)
	}
}
