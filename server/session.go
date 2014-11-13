package server

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
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
	sessionKeyValidityWindow = 10 * time.Minute

	//TODO(bcwaldon): make configurable
	idTokenValidityWindow = time.Hour
)

type sessionState string

const (
	sessionStateNew        = sessionState("NEW")
	sessionStateIdentified = sessionState("IDENTIFIED")
	sessionStateExchanged  = sessionState("EXCHANGED")
	sessionStateExpired    = sessionState("EXPIRED")
)

type SessionKey struct {
	value     string
	expiresAt time.Time
	used      bool
	session   *Session
}

type Session struct {
	State          sessionState
	CreatedAt      time.Time
	ClientIdentity oauth2.ClientIdentity
	ClientState    string
	Identity       oidc.Identity
	sessionManager *SessionManager
}

func NewSessionManager(issuerURL string, signer josesig.Signer) *SessionManager {
	return &SessionManager{
		issuerURL:    issuerURL,
		signer:       signer,
		sessions:     make([]*Session, 0),
		keys:         make(map[string]*SessionKey),
		generateCode: generateCode,
		clock:        clockwork.NewRealClock(),
	}
}

type SessionManager struct {
	issuerURL    string
	signer       josesig.Signer
	sessions     []*Session
	keys         map[string]*SessionKey
	generateCode generateCodeFunc
	clock        clockwork.Clock
}

func (m *SessionManager) NewSession(ci oauth2.ClientIdentity, cs string) *Session {
	s := &Session{
		State:          sessionStateNew,
		CreatedAt:      m.clock.Now().UTC(),
		ClientIdentity: ci,
		ClientState:    cs,
		sessionManager: m,
	}

	m.sessions = append(m.sessions, s)
	return s
}

func (m *SessionManager) newSessionKey(s *Session) string {
	k := &SessionKey{
		value:     m.generateCode(),
		expiresAt: m.clock.Now().UTC().Add(sessionKeyValidityWindow),
		session:   s,
	}
	m.keys[k.value] = k
	return k.value
}

func (m *SessionManager) Session(val string) *Session {
	k := m.keys[val]
	if k == nil {
		return nil
	}

	if k.expiresAt.Before(m.clock.Now().UTC()) {
		return nil
	}

	if k.used {
		return nil
	}

	k.used = true
	return k.session
}

func (s *Session) NewKey() string {
	return s.sessionManager.newSessionKey(s)
}

func (s *Session) Identify(ident oidc.Identity) error {
	if s.State != sessionStateNew {
		return fmt.Errorf("session state %s, expect %s", s.State, sessionStateNew)
	}

	s.Identity = ident
	s.State = sessionStateIdentified

	return nil
}

func (s *Session) IDToken() (*jose.JWT, error) {
	if s.State != sessionStateIdentified {
		return nil, fmt.Errorf("session state %s, expect %s", s.State, sessionStateIdentified)
	}

	claims := jose.Claims{
		// required
		"iss": s.sessionManager.issuerURL,
		"sub": s.Identity.ID,
		"aud": s.ClientIdentity.ID,
		// explicitly cast to float64 for consistent JSON (de)serialization
		"iat": float64(s.CreatedAt.Unix()),
		"exp": float64(s.CreatedAt.Add(idTokenValidityWindow).Unix()),

		// conventional
		"name":  s.Identity.Name,
		"email": s.Identity.Email,
	}

	jwt, err := josesig.NewSignedJWT(claims, s.sessionManager.signer)
	if err != nil {
		return nil, err
	}

	s.State = sessionStateExchanged
	return jwt, nil
}

type generateCodeFunc func() string

func generateCode() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(rand.Int63()))
	return base64.URLEncoding.EncodeToString(b)
}
