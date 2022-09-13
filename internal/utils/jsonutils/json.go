package jsonutils

import (
	"bytes"
	"encoding/json"
)

// IsJSONObject checks if the passed data is a JSON Object
func IsJSONObject(data []byte) bool {
	var d = struct{}{}
	return json.Unmarshal(data, &d) == nil
}

// IsJSONArray checks if the passed data is a JSON Array
func IsJSONArray(data []byte) bool {
	d := make([]interface{}, 0)
	return json.Unmarshal(data, &d) == nil
}

var emptyArray = []byte{
	'[',
	']',
}

// MergeJSONArrays merges two json arrays into one
func MergeJSONArrays(a1, a2 []byte) []byte {
	if bytes.Equal(bytes.Trim(a1, " "), emptyArray) {
		return a2
	}
	if bytes.Equal(bytes.Trim(a2, " "), emptyArray) {
		return a1
	}
	res := append(a1[:bytes.LastIndexByte(a1, ']')], ',') // skipcq: CRT-D0001
	res = append(res, a2[bytes.IndexByte(a2, '[')+1:]...)
	return res
}

// Arrayify creates an JSON array with the passed object in
func Arrayify(o []byte) []byte {
	return bytes.Join(
		[][]byte{
			{'['},
			o,
			{']'},
		}, nil,
	)
}

// UnwrapString removes the " around a string if they exist
func UnwrapString(s []byte) []byte {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
