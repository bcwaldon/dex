package session

import (
	"reflect"
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oidc"
)

func TestSessionClaims(t *testing.T) {
	issuerURL := "http://server.example.com"
	now := time.Now().UTC()

	tests := []struct {
		ses  Session
		want jose.Claims
	}{
		{
			ses: Session{
				CreatedAt: now,
				ExpiresAt: now.Add(time.Hour),
				ClientID:  "XXX",
				Identity: oidc.Identity{
					ID:    "YYY",
					Name:  "elroy",
					Email: "elroy@example.com",
				},
			},
			want: jose.Claims{
				"iss":   issuerURL,
				"sub":   "YYY",
				"aud":   "XXX",
				"iat":   float64(now.Unix()),
				"exp":   float64(now.Add(time.Hour).Unix()),
				"name":  "elroy",
				"email": "elroy@example.com",
			},
		},

		// Identity has custom ExpiresAt
		{
			ses: Session{
				CreatedAt: now,
				ExpiresAt: now.Add(time.Hour),
				ClientID:  "XXX",
				Identity: oidc.Identity{
					ID:        "YYY",
					Name:      "elroy",
					Email:     "elroy@example.com",
					ExpiresAt: now.Add(time.Minute),
				},
			},
			want: jose.Claims{
				"iss":   issuerURL,
				"sub":   "YYY",
				"aud":   "XXX",
				"iat":   float64(now.Unix()),
				"exp":   float64(now.Add(time.Minute).Unix()),
				"name":  "elroy",
				"email": "elroy@example.com",
			},
		},
	}

	for i, tt := range tests {
		got := tt.ses.Claims(issuerURL)
		if !reflect.DeepEqual(tt.want, got) {
			t.Fatalf("case %d: want=%#v got=%#v", i, tt.want, got)
		}
	}

}
