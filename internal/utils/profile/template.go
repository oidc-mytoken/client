package profile

import (
	"encoding/json"
	"path"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/oidc-mytoken/server/shared/utils/fileutil"
	"github.com/pkg/errors"

	"github.com/oidc-mytoken/client/internal/utils/jsonutils"
)

type readFnc func(string) ([]byte, error)

type TemplateReader struct {
	globalBaseDir string
	userBaseDir   string
	reader        readFnc
}

func init() {
	templateReader = newTemplateReader(fileutil.ReadFile)
}

var templateReader *TemplateReader

func newTemplateReader(reader readFnc) *TemplateReader {
	return &TemplateReader{
		globalBaseDir: "/etc/mytoken",
		userBaseDir:   userBasePath(),
		reader:        reader,
	}
}

func userBasePath() string {
	const conf = "~/.config/mytoken"
	const dot = "~/.mytoken"
	if fileutil.FileExists(conf) {
		return conf
	}
	return dot
}

func (r TemplateReader) ReadFile(relPath string) ([]byte, error) {
	globalP := path.Join(r.globalBaseDir, relPath)
	userP := path.Join(r.userBaseDir, relPath)
	global, _ := r.reader(globalP)
	user, _ := r.reader(userP)
	if len(user) == 0 {
		return global, nil
	}
	if len(global) == 0 {
		return user, nil
	}
	combined, _ := jsonpatch.MergePatch(global, user)
	return combined, nil
}

func (r TemplateReader) readRestrictionsTemplate(name string) ([]byte, error) {
	p := path.Join("restrictions.d", name)
	return r.ReadFile(p)
}
func (r TemplateReader) readCapabilityTemplate(name string) ([]byte, error) {
	p := path.Join("capabilities.d", name)
	return r.ReadFile(p)
}
func (r TemplateReader) readRotationTemplate(name string) ([]byte, error) {
	p := path.Join("rotation.d", name)
	return r.ReadFile(p)
}
func (r TemplateReader) readProfile(name string) ([]byte, error) {
	p := path.Join("profiles.d", name)
	return r.ReadFile(p)
}

func normalizeTemplateName(name string) string {
	if name != "" && name[0] == '!' {
		return name[1:]
	}
	return name
}

type includeTemplates struct {
	Include []string `json:"include"`
}

func createFinalTemplate(content []byte, read readFnc) ([]byte, error) {
	if len(content) == 0 {
		return nil, nil
	}
	baseIsArray := jsonutils.IsJSONArray(content)
	if baseIsArray {
		var contents []json.RawMessage
		if err := errors.WithStack(json.Unmarshal(content, &contents)); err != nil {
			return nil, err
		}
		final := []byte(`[]`)
		for _, c := range contents {
			cf, err := createFinalTemplate(c, read)
			if err != nil {
				return nil, err
			}
			if !jsonutils.IsJSONArray(cf) {
				cf = jsonutils.Arrayify(cf)
			}
			final = jsonutils.MergeJSONArrays(final, cf)
		}
		return final, nil
	}

	if !jsonutils.IsJSONObject(content) {
		// must be single template name
		c, err := read(normalizeTemplateName(string(content)))
		if err != nil {
			return nil, err
		}
		return createFinalTemplate(c, read)
	}
	var inc includeTemplates
	if err := errors.WithStack(json.Unmarshal(content, &inc)); err != nil {
		return nil, err
	}

	for _, inP := range inc.Include {
		c, err := read(normalizeTemplateName(inP))
		if err != nil {
			return nil, err
		}
		includeContent, err := createFinalTemplate(c, read)
		if err != nil {
			return nil, err
		}
		isArray := jsonutils.IsJSONArray(includeContent)
		if !baseIsArray && !isArray {
			content, _ = jsonpatch.MergePatch(includeContent, content)
			continue
		}
		if !baseIsArray {
			content = jsonutils.Arrayify(content)
			baseIsArray = true
		}
		if !isArray {
			includeContent = jsonutils.Arrayify(includeContent)
		}
		content = jsonutils.MergeJSONArrays(content, includeContent)
	}
	return content, nil
}
