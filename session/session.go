package session

import (
	"net/url"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oidc"
)

const (
	sessionKeyValidityWindow = 10 * time.Minute //RFC6749
	sessionValidityWindow    = time.Hour
)

type SessionState string

const (
	SessionStateNew        = SessionState("NEW")
	SessionStateIdentified = SessionState("IDENTIFIED")
	SessionStateDead       = SessionState("EXCHANGED")
)

type SessionKey struct {
	Key       string
	SessionID string
}

type Session struct {
	ID          string
	State       SessionState
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ClientID    string
	ClientState string
	RedirectURL url.URL
	Identity    oidc.Identity
}

func (s *Session) Claims(issuerURL string) jose.Claims {
	exp := s.Identity.ExpiresAt
	if exp.IsZero() {
		exp = s.ExpiresAt
	}

	return jose.Claims{
		// required
		"iss": issuerURL,
		"sub": s.Identity.ID,
		"aud": s.ClientID,
		"iat": float64(s.CreatedAt.Unix()),
		"exp": float64(exp.Unix()),

		// conventional
		"name":  s.Identity.Name,
		"email": s.Identity.Email,
	}
}
