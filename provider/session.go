package provider

import (
	"encoding/base64"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oidc"
)

type Session struct {
	AuthCode     string
	ClientID     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	AccessToken  string
	RefreshToken string
	Identity     oidc.Identity
}

func (ses *Session) IDToken(issuerURL string, signer josesig.Signer) (*jose.JWT, error) {
	claims := map[string]interface{}{
		// required
		"iss": issuerURL,
		"sub": ses.Identity.ID,
		"aud": ses.ClientID,
		// explicitly cast to float64 for consistent JSON (de)serialization
		"exp": float64(ses.ExpiresAt.Unix()),
		"iat": float64(ses.IssuedAt.Unix()),

		// conventional
		"name":  ses.Identity.Name,
		"email": ses.Identity.Email,
	}

	return oidc.NewSignedJWT(claims, signer)
}

func NewSessionManager() *SessionManager {
	return &SessionManager{make(map[string]*Session)}
}

type SessionManager struct {
	sessions map[string]*Session
}

func (m *SessionManager) NewSession(c Client, ident oidc.Identity) string {
	now := time.Now().UTC()
	s := Session{
		AuthCode:     genToken(),
		ClientID:     c.ID,
		IssuedAt:     now,
		ExpiresAt:    now.Add(30 * time.Second),
		AccessToken:  genToken(),
		RefreshToken: genToken(),
		Identity:     ident,
	}
	m.sessions[s.AuthCode] = &s
	return s.AuthCode
}

func (m *SessionManager) LookupByAuthCode(code string) *Session {
	return m.sessions[code]
}

func genToken() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(rand.Int63()))
	return base64.URLEncoding.EncodeToString(b)
}
