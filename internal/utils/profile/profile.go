package profile

import (
	"encoding/json"

	"github.com/imdario/mergo"
	"github.com/oidc-mytoken/api/v0"
)

type profileUnmarshal struct {
	api.GeneralMytokenRequest
	Restrictions         jsonraw  `json:"restrictions"`
	Capabilities         jsonraw  `json:"capabilities"`
	SubtokenCapabilities jsonraw  `json:"subtoken_capabilities"`
	Rotation             jsonraw  `json:"rotation"`
	IncludeProfiles      []string `json:"include"`
}

type jsonraw string

func (r *jsonraw) UnmarshalJSON(data []byte) error {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	rawStr := string(raw)
	if rawStr != "" && rawStr[0] == '"' && rawStr[len(rawStr)-1] == '"' {
		rawStr = rawStr[1 : len(rawStr)-1]
	}
	*r = jsonraw(rawStr)
	return nil
}

func parseProfileByName(name string) (api.GeneralMytokenRequest, error) {
	profileContent, err := readProfile(normalizeTemplateName(name))
	if err != nil {
		return api.GeneralMytokenRequest{}, err
	}
	return parseProfile(profileContent)
}

func parseProfile(content string) (api.GeneralMytokenRequest, error) {
	if content == "" {
		return api.GeneralMytokenRequest{}, nil
	}
	if !isJSONObject(content) {
		// must be single profile name
		return parseProfileByName(content)
	}
	var p profileUnmarshal
	var err error
	if err = json.Unmarshal([]byte(content), &p); err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.Rotation, err = parseRotationTemplate(string(p.Rotation))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.Capabilities, err = parseCapabilityTemplate(string(p.Capabilities))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.SubtokenCapabilities, err = parseCapabilityTemplate(string(p.SubtokenCapabilities))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.Restrictions, err = parseRestrictionsTemplate(string(p.Restrictions))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}

	for _, inP := range p.IncludeProfiles {
		includeReq, err := parseProfileByName(inP)
		if err != nil {
			return p.GeneralMytokenRequest, err
		}
		if err = mergo.Merge(&p.GeneralMytokenRequest, includeReq); err != nil {
			return p.GeneralMytokenRequest, err
		}
	}
	return p.GeneralMytokenRequest, nil
}
