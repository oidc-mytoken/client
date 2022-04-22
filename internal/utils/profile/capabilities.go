package profile

import (
	"encoding/json"
	"strings"

	"github.com/oidc-mytoken/api/v0"
	"github.com/oidc-mytoken/server/shared/utils"
)

func parseCapabilityTemplate(content string) (api.Capabilities, error) {
	capStrings, err := _parseCapabilityTemplate(content)
	capStrings = utils.UniqueSlice(capStrings)
	var caps api.Capabilities = nil
	if err == nil {
		caps = api.NewCapabilities(capStrings)
	}
	return caps, err
}

func _parseCapabilityTemplateByName(name string) ([]string, error) {
	templateContent, err := readCapabilityTemplate(name)
	if err != nil {
		return nil, err
	}
	return _parseCapabilityTemplate(templateContent)
}

func _parseCapabilityTemplate(content string) (capStrings []string, err error) {
	if content == "" {
		return nil, nil
	}
	var tmpCapStrings []string
	if isJSONArray(content) {
		if err = json.Unmarshal([]byte(content), &tmpCapStrings); err != nil {
			return
		}
	} else {
		tmpCapStrings = strings.Split(content, " ")
	}
	for _, c := range tmpCapStrings {
		if !strings.HasPrefix(c, "!") {
			capStrings = append(capStrings, c)
		} else {
			templateCaps, e := _parseCapabilityTemplateByName(c[1:])
			if e != nil {
				err = e
				return
			}
			if len(templateCaps) > 0 {
				capStrings = append(capStrings, templateCaps...)
			}
		}
	}
	return
}
