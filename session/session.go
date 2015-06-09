package session

import (
	"net/url"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oidc"
)

const (
	sessionKeyValidityWindow     = 10 * time.Minute //RFC6749
	defaultSessionValidityWindow = 12 * time.Hour
)

type SessionState string

const (
	SessionStateNew            = SessionState("NEW")
	SessionStateRemoteAttached = SessionState("REMOTE_ATTACHED")
	SessionStateIdentified     = SessionState("IDENTIFIED")
	SessionStateDead           = SessionState("EXCHANGED")
)

type SessionKey struct {
	Key       string
	SessionID string
}

type Session struct {
	ConnectorID string
	ID          string
	State       SessionState
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ClientID    string
	ClientState string
	RedirectURL url.URL
	Identity    oidc.Identity
	UserID      string

	// Indicates that this session is a registration flow.
	Register bool
}

// Claims returns a new set of Claims for the current session.
// The "sub" of the returned Claims is that of the authd User, not whatever
// remote Identity was used to authenticate. However the "email" from the
// Identity is used.
func (s *Session) Claims(issuerURL string) jose.Claims {
	claims := oidc.NewClaims(issuerURL, s.UserID, s.ClientID, s.CreatedAt, s.ExpiresAt)
	return claims
}
