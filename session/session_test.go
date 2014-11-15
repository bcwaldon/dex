package session

import (
	"reflect"
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

func TestSessionIDToken(t *testing.T) {
	issuerURL := "http://server.example.com"
	now := time.Now().UTC()
	ses := &Session{
		CreatedAt: now,
		ClientIdentity: oauth2.ClientIdentity{
			ID: "XXX",
		},
		Identity: oidc.Identity{
			ID:    "YYY",
			Name:  "elroy",
			Email: "elroy@example.com",
		},
	}
	want := jose.Claims{
		// required
		"iss": issuerURL,
		"sub": "YYY",
		"aud": "XXX",
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(time.Hour).Unix()),

		// conventional
		"name":  "elroy",
		"email": "elroy@example.com",
	}

	got := ses.Claims(issuerURL)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("Incorrect claims: want=%#v got=%#v", want, got)
	}
}
