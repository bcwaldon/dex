package oidc

import (
	"reflect"
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
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

	k, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Unable to generate private key: %v", err)
	}
	okKS := key.NewPublicKeySet([]jose.JWK{k.JWK()}, now.Add(time.Hour))
	expKS := key.NewPublicKeySet([]jose.JWK{k.JWK()}, now.Add(time.Hour*-1))

	okCfg := ProviderConfig{
		ExpiresAt: now.Add(time.Hour),
	}
	expCfg := ProviderConfig{
		ExpiresAt: now.Add(time.Hour * -1),
	}

	tests := []struct {
		c *Client
		h bool
	}{
		// all ok
		{
			c: &Client{
				ProviderConfig: okCfg,
				KeySet:         *okKS,
			},
			h: true,
		},
		// expired config
		{
			c: &Client{
				ProviderConfig: expCfg,
				KeySet:         *okKS,
			},
			h: false,
		},
		// expired keyset
		{
			c: &Client{
				ProviderConfig: okCfg,
				KeySet:         *expKS,
			},
			h: false,
		},
		// missing config
		{
			c: &Client{
				KeySet: *okKS,
			},
			h: false,
		},
		// missing keyset
		{
			c: &Client{
				ProviderConfig: okCfg,
			},
			h: false,
		},
		// empty client
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
			t.Errorf("case %d: want: healhty=%v, got: healhty=%v, err: %v", i, want, got, err)
		}
	}
}
