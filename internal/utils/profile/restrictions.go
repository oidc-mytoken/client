package profile

import (
	"encoding/json"

	"github.com/imdario/mergo"
	"github.com/oidc-mytoken/api/v0"

	"github.com/oidc-mytoken/client/internal/utils"
)

func parseRestrictionsTemplateByName(name string) (api.Restrictions, error) {
	templateContent, err := readRestrictionsTemplate(normalizeTemplateName(name))
	if err != nil {
		return api.Restrictions{}, err
	}
	return parseRestrictionsTemplate(templateContent)
}

type restrictionTemplateMarshal struct {
	utils.APIRestriction
	includes
}

type includes struct {
	IncludeTemplates []string `json:"include"`
}

func (r *restrictionTemplateMarshal) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &r.APIRestriction); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &r.includes); err != nil {
		return err
	}
	return nil
}

func parseRestrictionsTemplate(content string) (api.Restrictions, error) {
	if content == "" {
		return nil, nil
	}
	restrs := make([]restrictionTemplateMarshal, 0)
	if isJSONObject(content) {
		content = "[" + content + "]"
	}
	if !isJSONArray(content) {
		// single template name
		return parseRestrictionsTemplateByName(content)
	}
	if err := json.Unmarshal([]byte(content), &restrs); err != nil {
		return nil, err
	}
	finalRestrs := make([]api.Restriction, 0)
	for _, r := range restrs {
		templateRestrs := make([]api.Restriction, 0)
		for _, t := range r.IncludeTemplates {
			templateRestrictions, err := parseRestrictionsTemplateByName(t)
			if err != nil {
				return nil, err
			}
			if len(templateRestrictions) > 0 {
				if err = mergo.Merge(&r.APIRestriction, utils.APIRestriction(templateRestrictions[0])); err != nil {
					return nil, err
				}
			}
			if len(templateRestrictions) > 1 {
				templateRestrs = append(templateRestrs, templateRestrictions[1:]...)
			}
		}
		finalRestrs = append(finalRestrs, api.Restriction(r.APIRestriction))
		finalRestrs = append(finalRestrs, templateRestrs...)
	}
	return finalRestrs, nil
}
