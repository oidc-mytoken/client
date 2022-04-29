package profile

import (
	"encoding/json"
	"reflect"

	"github.com/oidc-mytoken/api/v0"
	"github.com/pkg/errors"

	"github.com/oidc-mytoken/client/internal/utils"
	"github.com/oidc-mytoken/client/internal/utils/jsonutils"
)

func parseRestrictionsTemplateByName(name string) (api.Restrictions, error) {
	content, err := templateReader.readRestrictionsTemplate(normalizeTemplateName(name))
	if err != nil {
		return nil, err
	}
	return parseRestrictionsTemplate(content)
}

func parseRestrictionsTemplate(content []byte) (api.Restrictions, error) {
	if len(content) == 0 {
		return nil, nil
	}
	if jsonutils.IsJSONObject(content) {
		content = jsonutils.Arrayify(content)
	}
	if !jsonutils.IsJSONArray(content) {
		// single template name
		return parseRestrictionsTemplateByName(string(content))
	}

	var err error
	var restr []utils.APIRestriction
	content, err = createFinalTemplate(content, templateReader.readRestrictionsTemplate)
	if err != nil {
		return nil, err
	}
	if err = errors.WithStack(json.Unmarshal(content, &restr)); err != nil {
		return nil, err
	}
	finalRestrs := make([]api.Restriction, 0)
	for _, r := range restr {
		if !reflect.DeepEqual(r, utils.APIRestriction{}) {
			finalRestrs = append(finalRestrs, api.Restriction(r))
		}
	}
	return finalRestrs, nil
}
