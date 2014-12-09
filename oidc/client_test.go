package oidc

import (
	"reflect"
	"testing"
)

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
