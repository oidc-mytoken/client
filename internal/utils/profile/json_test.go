package profile

import (
	"testing"
)

func TestIsJSONObject(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		result bool
	}{
		{
			name:   "empty",
			data:   "",
			result: false,
		},
		{
			name:   "empty object",
			data:   "{}",
			result: true,
		},
		{
			name:   "string",
			data:   "string",
			result: false,
		},
		{
			name:   "object",
			data:   `{"key":"value"}`,
			result: true,
		},
		{
			name:   "no valid object",
			data:   `{something within braces}`,
			result: false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if test.result != isJSONObject(test.data) {
					t.Errorf("isJSONObject('%s') != %v", test.data, test.result)
				}
			},
		)
	}
}

func TestIsJSONArray(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		result bool
	}{
		{
			name:   "empty",
			data:   "",
			result: false,
		},
		{
			name:   "empty array",
			data:   "[]",
			result: true,
		},
		{
			name:   "string",
			data:   "string",
			result: false,
		},
		{
			name:   "array with strings",
			data:   `["key","other"]`,
			result: true,
		},
		{
			name:   "array with objects",
			data:   `[{"key":"value"},{"key":"other"}]`,
			result: true,
		},
		{
			name:   "mixed",
			data:   `["string", {"object": true}]`,
			result: true,
		},
		{
			name:   "no valid array",
			data:   `[something within braces]`,
			result: false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if test.result != isJSONArray(test.data) {
					t.Errorf("isJSONArray('%s') != %v", test.data, test.result)
				}
			},
		)
	}
}
