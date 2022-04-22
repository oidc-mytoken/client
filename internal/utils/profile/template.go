package profile

import (
	"fmt"
)

func readRestrictionsTemplate(name string) (string, error) {
	path := fmt.Sprintf("restrictions.d/%s", name)
	return readTemplate(path)
}
func readCapabilityTemplate(name string) (string, error) {
	path := fmt.Sprintf("capabilities.d/%s", name)
	return readTemplate(path)
}
func readRotationTemplate(name string) (string, error) {
	path := fmt.Sprintf("rotation.d/%s", name)
	return readTemplate(path)
}
func readProfile(name string) (string, error) {
	path := fmt.Sprintf("profiles.d/%s", name)
	return readTemplate(path)
}

func readTemplate(path string) (string, error) {
	return profile_template_dummy_data[path], nil
}

func normalizeTemplateName(name string) string {
	if name != "" && name[0] == '!' {
		return name[1:]
	}
	return name
}
