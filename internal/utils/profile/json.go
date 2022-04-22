package profile

import (
	"encoding/json"
)

func isJSONObject(data string) bool {
	var d = struct{}{}
	return json.Unmarshal([]byte(data), &d) == nil
}
func isJSONArray(data string) bool {
	d := make([]interface{}, 0)
	return json.Unmarshal([]byte(data), &d) == nil
}
