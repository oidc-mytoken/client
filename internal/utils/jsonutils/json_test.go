package jsonutils

import (
	"bytes"
	"testing"
)

func Test_IsJSONObject(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		result bool
	}{
		{
			name:   "nil",
			data:   nil,
			result: false,
		},
		{
			name:   "empty",
			data:   []byte{},
			result: false,
		},
		{
			name:   "empty object",
			data:   []byte("{}"),
			result: true,
		},
		{
			name:   "string",
			data:   []byte("string"),
			result: false,
		},
		{
			name:   "object",
			data:   []byte(`{"key":"value"}`),
			result: true,
		},
		{
			name:   "no valid object",
			data:   []byte(`{something within braces}`),
			result: false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if test.result != IsJSONObject(test.data) {
					t.Errorf("IsJSONObject('%s') != %v", test.data, test.result)
				}
			},
		)
	}
}

func Test_IsJSONArray(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		result bool
	}{
		{
			name:   "nil",
			data:   nil,
			result: false,
		},
		{
			name:   "empty",
			data:   []byte{},
			result: false,
		},
		{
			name:   "empty array",
			data:   []byte("[]"),
			result: true,
		},
		{
			name:   "string",
			data:   []byte("string"),
			result: false,
		},
		{
			name:   "array with strings",
			data:   []byte(`["key","other"]`),
			result: true,
		},
		{
			name:   "array with objects",
			data:   []byte(`[{"key":"value"},{"key":"other"}]`),
			result: true,
		},
		{
			name:   "mixed",
			data:   []byte(`["string", {"object": true}]`),
			result: true,
		},
		{
			name:   "no valid array",
			data:   []byte(`[something within braces]`),
			result: false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if test.result != IsJSONArray(test.data) {
					t.Errorf("IsJSONArray('%s') != %v", test.data, test.result)
				}
			},
		)
	}
}

func Test_MergeJSONArrays(t *testing.T) {
	tests := []struct {
		name     string
		a1       []byte
		a2       []byte
		expected []byte
	}{
		{
			name:     "empty",
			a1:       []byte(`[]`),
			a2:       []byte(`[]`),
			expected: []byte(`[]`),
		},
		{
			name:     "first empty",
			a1:       []byte(`[]`),
			a2:       []byte(`["a","b"]`),
			expected: []byte(`["a","b"]`),
		},
		{
			name:     "second empty",
			a1:       []byte(`["a","b"]`),
			a2:       []byte(`[]`),
			expected: []byte(`["a","b"]`),
		},
		{
			name:     "normal",
			a1:       []byte(`["a","b"]`),
			a2:       []byte(`["c"]`),
			expected: []byte(`["a","b","c"]`),
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				res := MergeJSONArrays(test.a1, test.a2)
				if !bytes.Equal(test.expected, res) {
					t.Errorf("MergeJSONArrays() = %v, want %v", res, test.expected)
				}
			},
		)
	}
}
