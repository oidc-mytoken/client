package profile

import (
	"encoding/json"

	"github.com/oidc-mytoken/api/v0"
	"github.com/pkg/errors"
)

func parseRotationTemplateByName(name string) (*api.Rotation, error) {
	content, err := templateReader.readRotationTemplate(normalizeTemplateName(name))
	if err != nil {
		return nil, err
	}
	return ParseRotationTemplate(content)
}

// ParseRotationTemplate parses the content of a rotation template
func ParseRotationTemplate(content []byte) (*api.Rotation, error) {
	if len(content) == 0 {
		return nil, nil
	}
	var err error
	var rot api.Rotation
	content, err = createFinalTemplate(content, templateReader.readRotationTemplate)
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, nil
	}
	err = errors.WithStack(json.Unmarshal(content, &rot))
	return &rot, err
}
