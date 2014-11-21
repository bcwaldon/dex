package session

import (
	"net/url"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oidc"
)

const (
	// 10min recommended by RFC6749
	sessionKeyValidityWindow = 10 * time.Minute

	//TODO(bcwaldon): make configurable
	idTokenValidityWindow = time.Hour
)

type sessionState string

const (
	sessionStateNew        = sessionState("NEW")
	sessionStateIdentified = sessionState("IDENTIFIED")
	sessionStateDead       = sessionState("EXCHANGED")
)

type SessionKey struct {
	Key       string
	SessionID string
	ExpiresAt time.Time
}

type Session struct {
	ID          string
	State       sessionState
	CreatedAt   time.Time
	ClientID    string
	ClientState string
	RedirectURL url.URL
	Identity    oidc.Identity
}

func (s *Session) Claims(issuerURL string) jose.Claims {
	return jose.Claims{
		// required
		"iss": issuerURL,
		"sub": s.Identity.ID,
		"aud": s.ClientID,
		// explicitly cast to float64 for consistent JSON (de)serialization
		"iat": float64(s.CreatedAt.Unix()),
		"exp": float64(s.CreatedAt.Add(idTokenValidityWindow).Unix()),

		// conventional
		"name":  s.Identity.Name,
		"email": s.Identity.Email,
	}
}
