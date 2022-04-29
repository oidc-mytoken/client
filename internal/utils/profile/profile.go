package profile

import (
	"encoding/json"

	"github.com/oidc-mytoken/api/v0"
	"github.com/pkg/errors"
)

type profileUnmarshal struct {
	api.GeneralMytokenRequest
	Restrictions         jsonraw `json:"restrictions"`
	Capabilities         jsonraw `json:"capabilities"`
	SubtokenCapabilities jsonraw `json:"subtoken_capabilities"`
	Rotation             jsonraw `json:"rotation"`
}

type jsonraw string

func (r *jsonraw) UnmarshalJSON(data []byte) error {
	var raw json.RawMessage
	if err := errors.WithStack(json.Unmarshal(data, &raw)); err != nil {
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
	content, err := templateReader.readProfile(normalizeTemplateName(name))
	if err != nil {
		return api.GeneralMytokenRequest{}, err
	}
	return parseProfile(content)
}

func parseProfile(content []byte) (api.GeneralMytokenRequest, error) {
	if len(content) == 0 {
		return api.GeneralMytokenRequest{}, nil
	}
	var err error
	var p profileUnmarshal
	content, err = createFinalTemplate(content, templateReader.readProfile)
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	if err = errors.WithStack(json.Unmarshal(content, &p)); err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.Rotation, err = parseRotationTemplate([]byte(p.Rotation))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.Capabilities, err = parseCapabilityTemplate([]byte(p.Capabilities))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.SubtokenCapabilities, err = parseCapabilityTemplate([]byte(p.SubtokenCapabilities))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	p.GeneralMytokenRequest.Restrictions, err = parseRestrictionsTemplate([]byte(p.Restrictions))
	if err != nil {
		return p.GeneralMytokenRequest, err
	}
	return p.GeneralMytokenRequest, nil
}
