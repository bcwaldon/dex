package oidc

import (
	"reflect"
	"testing"
	"time"
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

func TestHealthy(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		c *Client
		h bool
	}{
		// all ok
		{
			c: &Client{
				ProviderConfig: ProviderConfig{
					Issuer:    "http://example.com",
					ExpiresAt: now.Add(time.Hour),
				},
			},
			h: true,
		},
		// expired ProviderConfig
		{
			c: &Client{
				ProviderConfig: ProviderConfig{
					Issuer:    "http://example.com",
					ExpiresAt: now.Add(time.Hour * -1),
				},
			},
			h: false,
		},
		// empty ProviderConfig
		{
			c: &Client{},
			h: false,
		},
	}

	for i, tt := range tests {
		err := tt.c.Healthy()
		want := tt.h
		got := (err == nil)

		if want != got {
			t.Errorf("case %d: want: healthy=%v, got: healhty=%v, err: %v", i, want, got, err)
		}
	}
}
