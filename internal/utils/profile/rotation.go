package profile

import (
	"encoding/json"

	"github.com/imdario/mergo"
	"github.com/oidc-mytoken/api/v0"
)

func parseRotationTemplateByName(name string) (*api.Rotation, error) {
	templateContent, err := readRotationTemplate(normalizeTemplateName(name))
	if err != nil {
		return nil, err
	}
	return parseRotationTemplate(templateContent)
}

func parseRotationTemplate(content string) (*api.Rotation, error) {
	if content == "" {
		return nil, nil
	}
	rot := struct {
		*api.Rotation
		IncludeTemplates []string `json:"include"`
	}{}
	if !isJSONObject(content) {
		// single template name
		return parseRotationTemplateByName(content)
	}
	if err := json.Unmarshal([]byte(content), &rot); err != nil {
		return nil, err
	}
	for _, t := range rot.IncludeTemplates {
		templateRotation, err := parseRotationTemplateByName(t)
		if err != nil {
			return nil, err
		}
		if err = mergo.Merge(&rot.Rotation, templateRotation); err != nil {
			return nil, err
		}
	}
	return rot.Rotation, nil
}
