package oidc

import (
	"reflect"
	"testing"
	"time"
)

func TestNewClientScopeDefault(t *testing.T) {
	tests := []struct {
		c ClientConfig
		e []string
	}{
		{
			// No scope
			c: ClientConfig{},
			e: DefaultScope,
		},
		{
			// Nil scope
			c: ClientConfig{Scope: nil},
			e: DefaultScope,
		},
		{
			// Empty scope
			c: ClientConfig{Scope: []string{}},
			e: []string{},
		},
		{
			// Custom scope equal to default
			c: ClientConfig{Scope: []string{"openid", "email", "profile"}},
			e: DefaultScope,
		},
		{
			// Custom scope not including defaults
			c: ClientConfig{Scope: []string{"foo", "bar"}},
			e: []string{"foo", "bar"},
		},
		{
			// Custom scopes overlapping with defaults
			c: ClientConfig{Scope: []string{"openid", "foo"}},
			e: []string{"openid", "foo"},
		},
	}

	for i, tt := range tests {
		c, err := NewClient(tt.c)
		if err != nil {
			t.Errorf("case %d: unexpected error from NewClient: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(tt.e, c.Scope) {
			t.Errorf("case %d: want: %v, got: %v", i, tt.e, c.Scope)
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
		// zero-value ProviderConfig.ExpiresAt
		{
			c: &Client{
				ProviderConfig: ProviderConfig{
					Issuer: "http://example.com",
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
