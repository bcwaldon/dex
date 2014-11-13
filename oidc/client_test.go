package oidc

import (
	"net/http"
	"reflect"
	"testing"
)

func TestParseTokenFromRequestValid(t *testing.T) {
	tests := []string{"", "x", "Bearer", "xxxxxxx", "Bearer NotARealToken"}

	for i, tt := range tests {
		r, _ := http.NewRequest("", "", nil)
		r.Header.Add("Authorization", tt)
		_, err := ParseTokenFromRequest(r)
		if err == nil {
			t.Errorf("case %d: want: invalid Authorization header, got: valid Authorization header.", i)
		}
	}
}

func TestParseTokenFromRequestInvalid(t *testing.T) {
	tests := []string{
		"Bearer eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}

	for i, tt := range tests {
		r, _ := http.NewRequest("", "", nil)
		r.Header.Add("Authorization", tt)
		_, err := ParseTokenFromRequest(r)
		if err != nil {
			t.Errorf("case %d: want: valid Authorization header, got: invalid Authorization header: %v.", i, err)
		}
	}
}

func TestGetScopeDefault(t *testing.T) {
	tests := []struct {
		c *Client
		e []string
	}{
		{
			// No scope
			c: &Client{},
			e: DefaultScope,
		},
		{
			// Nil scope
			c: &Client{Scope: nil},
			e: DefaultScope,
		},
		{
			// Empty scope
			c: &Client{Scope: []string{}},
			e: []string{},
		},
		{
			// Custom scope equal to default
			c: &Client{Scope: []string{"openid", "email", "profile"}},
			e: DefaultScope,
		},
		{
			// Custom scope not including defaults
			c: &Client{Scope: []string{"foo", "bar"}},
			e: []string{"foo", "bar"},
		},
		{
			// Custom scopes overlapping with defaults
			c: &Client{Scope: []string{"openid", "foo"}},
			e: []string{"openid", "foo"},
		},
	}

	for i, tt := range tests {
		s := tt.c.getScope()
		if !reflect.DeepEqual(tt.e, s) {
			t.Errorf("case %d: want: %v, got: %v", i, tt.e, s)
		}
	}
}
