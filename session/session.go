package session

import (
	"net/url"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oidc"
)

const (
	sessionKeyValidityWindow     = 10 * time.Minute //RFC6749
	defaultSessionValidityWindow = time.Hour
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

	claims := oidc.NewClaims(issuerURL, s.Identity.ID, s.ClientID, s.CreatedAt, exp)
	claims.Add("name", s.Identity.Name)
	claims.Add("email", s.Identity.Email)

	return claims
}
