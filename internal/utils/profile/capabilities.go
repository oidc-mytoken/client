package profile

import (
	"encoding/json"
	"strings"

	"github.com/oidc-mytoken/api/v0"
	"github.com/oidc-mytoken/server/shared/utils"
	"github.com/pkg/errors"

	"github.com/oidc-mytoken/client/internal/utils/jsonutils"
)

// ParseCapabilityTemplate parses the content of a capability template
func ParseCapabilityTemplate(content []byte) (api.Capabilities, error) {
	capStrings, err := _parseCapabilityTemplate(content)
	capStrings = utils.UniqueSlice(capStrings)
	var caps api.Capabilities = nil
	if err == nil {
		caps = api.NewCapabilities(capStrings)
	}
	return caps, err
}

func _parseCapabilityTemplateByName(name string) ([]string, error) {
	content, err := templateReader.readCapabilityTemplate(normalizeTemplateName(name))
	if err != nil {
		return nil, err
	}
	return _parseCapabilityTemplate(content)
}

func _parseCapabilityTemplate(content []byte) (capStrings []string, err error) {
	if len(content) == 0 {
		return nil, nil
	}
	var tmpCapStrings []string
	if jsonutils.IsJSONArray(content) {
		if err = errors.WithStack(json.Unmarshal(content, &tmpCapStrings)); err != nil {
			return
		}
	} else {
		tmpCapStrings = strings.Split(string(content), " ")
	}
	for _, c := range tmpCapStrings {
		if !strings.HasPrefix(c, "@") {
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
