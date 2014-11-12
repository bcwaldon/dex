package server

import (
	"encoding/base64"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

type Session struct {
	AuthCode       string
	ClientIdentity oauth2.ClientIdentity
	IssuedAt       time.Time
	ExpiresAt      time.Time
	IDToken        jose.JWT
}

func NewSessionManager(issuerURL string, signer josesig.Signer) *SessionManager {
	return &SessionManager{
		issuerURL: issuerURL,
		signer:    signer,
		sessions:  make(map[string]*Session),
	}
}

type SessionManager struct {
	issuerURL string
	signer    josesig.Signer
	sessions  map[string]*Session
}

func (m *SessionManager) NewSession(ci oauth2.ClientIdentity, ident oidc.Identity) (string, error) {
	now := time.Now().UTC()

	s := Session{
		AuthCode:       genToken(),
		ClientIdentity: ci,
		IssuedAt:       now,
		ExpiresAt:      now.Add(30 * time.Second),
	}

	claims := jose.Claims{
		// required
		"iss": m.issuerURL,
		"sub": ident.ID,
		"aud": s.ClientIdentity.ID,
		// explicitly cast to float64 for consistent JSON (de)serialization
		"exp": float64(s.ExpiresAt.Unix()),
		"iat": float64(s.IssuedAt.Unix()),

		// conventional
		"name":  ident.Name,
		"email": ident.Email,
	}

	jwt, err := josesig.NewSignedJWT(claims, m.signer)
	if err != nil {
		return "", err
	}

	s.IDToken = *jwt

	m.sessions[s.AuthCode] = &s
	return s.AuthCode, nil
}

func (m *SessionManager) LookupByAuthCode(code string) *Session {
	return m.sessions[code]
}

func genToken() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(rand.Int63()))
	return base64.URLEncoding.EncodeToString(b)
}
