package session

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/url"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/oidc"
)

type GenerateCodeFunc func() string

func DefaultGenerateCode() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(rand.Int63()))
	return base64.URLEncoding.EncodeToString(b)
}

func NewSessionManager(sRepo SessionRepo, skRepo SessionKeyRepo) *SessionManager {
	return &SessionManager{
		GenerateCode: DefaultGenerateCode,
		Clock:        clockwork.NewRealClock(),
		sessions:     sRepo,
		keys:         skRepo,
	}
}

type SessionManager struct {
	GenerateCode GenerateCodeFunc
	Clock        clockwork.Clock
	sessions     SessionRepo
	keys         SessionKeyRepo
}

func (m *SessionManager) NewSession(clientID, clientState string, redirectURL url.URL) (string, error) {
	s := Session{
		ID:          m.GenerateCode(),
		State:       SessionStateNew,
		CreatedAt:   m.Clock.Now().UTC(),
		ClientID:    clientID,
		ClientState: clientState,
		RedirectURL: redirectURL,
	}

	err := m.sessions.Create(s)
	if err != nil {
		return "", err
	}
	return s.ID, nil
}

func (m *SessionManager) NewSessionKey(sessionID string) (string, error) {
	k := SessionKey{
		Key:       m.GenerateCode(),
		SessionID: sessionID,
	}
	err := m.keys.Push(k, sessionKeyValidityWindow)
	if err != nil {
		return "", err
	}
	return k.Key, nil
}

func (m *SessionManager) ExchangeKey(key string) (string, error) {
	return m.keys.Pop(key)
}

func (m *SessionManager) getSessionInState(sessionID string, state SessionState) (*Session, error) {
	s, err := m.sessions.Get(sessionID)
	if err != nil {
		return nil, err
	}

	if s.State != state {
		return nil, fmt.Errorf("session state %s, expect %s", s.State, state)
	}

	return s, nil
}

func (m *SessionManager) Identify(sessionID string, ident oidc.Identity) (*Session, error) {
	s, err := m.getSessionInState(sessionID, SessionStateNew)
	if err != nil {
		return nil, err
	}

	s.Identity = ident
	s.State = SessionStateIdentified

	if err = m.sessions.Update(*s); err != nil {
		return nil, err
	}

	return s, nil
}

func (m *SessionManager) Kill(sessionID string) (*Session, error) {
	s, err := m.sessions.Get(sessionID)
	if err != nil {
		return nil, err
	}

	s.State = SessionStateDead

	if err = m.sessions.Update(*s); err != nil {
		return nil, err
	}

	return s, nil
}
