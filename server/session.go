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
	"github.com/jonboulle/clockwork"
)

const (
	// 10min recommended by RFC6749
	authCodeValidityWindow = 10 * time.Minute

	//TODO(bcwaldon): make configurable
	idTokenValidityWindow = time.Hour
)

const (
	SessionStateNew       = SessionState("new")
	SessionStateExchanged = SessionState("exchanged")
	SessionStateExpired   = SessionState("expired")
)

type SessionState string

type Session struct {
	State          SessionState
	AuthCode       string
	ExpiresAt      time.Time
	ClientIdentity oauth2.ClientIdentity
	IDToken        jose.JWT
}

func NewSessionManager(issuerURL string, signer josesig.Signer) *SessionManager {
	return &SessionManager{
		issuerURL:    issuerURL,
		signer:       signer,
		sessions:     make(map[string]*Session),
		generateCode: generateCode,
		clock:        clockwork.NewRealClock(),
	}
}

type SessionManager struct {
	issuerURL    string
	signer       josesig.Signer
	sessions     map[string]*Session
	generateCode generateCodeFunc
	clock        clockwork.Clock
}

func (m *SessionManager) NewSession(ci oauth2.ClientIdentity, ident oidc.Identity) (*Session, error) {
	now := m.clock.Now().UTC()

	claims := jose.Claims{
		// required
		"iss": m.issuerURL,
		"sub": ident.ID,
		"aud": ci.ID,
		// explicitly cast to float64 for consistent JSON (de)serialization
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(idTokenValidityWindow).Unix()),

		// conventional
		"name":  ident.Name,
		"email": ident.Email,
	}

	jwt, err := josesig.NewSignedJWT(claims, m.signer)
	if err != nil {
		return nil, err
	}

	s := &Session{
		State:          SessionStateNew,
		AuthCode:       m.generateCode(),
		ExpiresAt:      now.Add(authCodeValidityWindow),
		ClientIdentity: ci,
		IDToken:        *jwt,
	}

	m.sessions[s.AuthCode] = s
	return s, nil
}

func (m *SessionManager) Exchange(ci oauth2.ClientIdentity, code string) *Session {
	ses := m.sessions[code]
	if ses == nil {
		return nil
	}

	if !ses.ClientIdentity.Match(ci) {
		return nil
	}

	if ses.State != SessionStateNew {
		return nil
	}

	if ses.ExpiresAt.Before(m.clock.Now().UTC()) {
		ses.State = SessionStateExpired
		return nil
	}

	ses.State = SessionStateExchanged
	return ses
}

type generateCodeFunc func() string

func generateCode() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(rand.Int63()))
	return base64.URLEncoding.EncodeToString(b)
}
