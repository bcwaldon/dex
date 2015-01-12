package oidc

import (
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
)

func TestVerifyClientClaims(t *testing.T) {
	validIss := "https://example.com"
	validClientID := "valid-client"
	now := time.Now()
	tomorrow := now.Add(24 * time.Hour)
	header := jose.JOSEHeader{
		jose.HeaderKeyAlgorithm: "test-alg",
		jose.HeaderKeyID:        "1",
	}

	tests := []struct {
		claims jose.Claims
		ok     bool
	}{
		// valid token
		{
			claims: jose.Claims{
				"iss": validIss,
				"sub": validClientID,
				"aud": validClientID,
				"iat": float64(now.Unix()),
				"exp": float64(tomorrow.Unix()),
			},
			ok: true,
		},
		// missing 'iss' claim
		{
			claims: jose.Claims{
				"sub": validClientID,
				"aud": validClientID,
				"iat": float64(now.Unix()),
				"exp": float64(tomorrow.Unix()),
			},
			ok: false,
		},
		// invalid 'iss' claim
		{
			claims: jose.Claims{
				"iss": "INVALID",
				"sub": validClientID,
				"aud": validClientID,
				"iat": float64(now.Unix()),
				"exp": float64(tomorrow.Unix()),
			},
			ok: false,
		},
		// missing 'sub' claim
		{
			claims: jose.Claims{
				"iss": validIss,
				"aud": validClientID,
				"iat": float64(now.Unix()),
				"exp": float64(tomorrow.Unix()),
			},
			ok: false,
		},
		// invalid 'sub' claim
		{
			claims: jose.Claims{
				"iss": validIss,
				"sub": "INVALID",
				"aud": validClientID,
				"iat": float64(now.Unix()),
				"exp": float64(tomorrow.Unix()),
			},
			ok: false,
		},
		// missing 'aud' claim
		{
			claims: jose.Claims{
				"iss": validIss,
				"sub": validClientID,
				"iat": float64(now.Unix()),
				"exp": float64(tomorrow.Unix()),
			},
			ok: false,
		},
		// invalid 'aud' claim
		{
			claims: jose.Claims{
				"iss": validIss,
				"sub": validClientID,
				"aud": "INVALID",
				"iat": float64(now.Unix()),
				"exp": float64(tomorrow.Unix()),
			},
			ok: false,
		},
		// expired
		{
			claims: jose.Claims{
				"iss": validIss,
				"sub": validClientID,
				"aud": validClientID,
				"iat": float64(now.Unix()),
				"exp": float64(now.Unix()),
			},
			ok: false,
		},
	}

	for i, tt := range tests {
		jwt, err := jose.NewJWT(header, tt.claims)
		if err != nil {
			t.Fatalf("case %d: Failed to generate JWT, error=%v", i, err)
		}

		got, err := VerifyClientClaims(jwt, validIss)
		if tt.ok {
			if err != nil {
				t.Errorf("case %d: unexpected error, err=%v", i, err)
			}
			if got != validClientID {
				t.Errorf("case %d: incorrect client ID, want=%s, got=%s", i, validClientID, got)
			}
		} else if err == nil {
			t.Errorf("case %d: expected error but err is nil", i)
		}
	}
}
