package session

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

type GenerateCodeFunc func() string

func DefaultGenerateCode() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(rand.Int63()))
	return base64.URLEncoding.EncodeToString(b)
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		GenerateCode: DefaultGenerateCode,
		Clock:        clockwork.NewRealClock(),
		sessions:     newSessionRepo(),
		keys:         newSessionKeyRepo(),
	}
}

type SessionManager struct {
	GenerateCode GenerateCodeFunc
	Clock        clockwork.Clock
	sessions     sessionRepo
	keys         sessionKeyRepo
}

func (m *SessionManager) NewSession(ci oauth2.ClientIdentity, cs string) (string, error) {
	s := Session{
		ID:             m.GenerateCode(),
		State:          sessionStateNew,
		CreatedAt:      m.Clock.Now().UTC(),
		ClientIdentity: ci,
		ClientState:    cs,
	}

	err := m.sessions.Set(s)
	if err != nil {
		return "", err
	}
	return s.ID, nil
}

func (m *SessionManager) NewSessionKey(sessionID string) (string, error) {
	k := sessionKey{
		key:       m.GenerateCode(),
		sessionID: sessionID,
	}
	err := m.keys.Push(k, sessionKeyValidityWindow)
	if err != nil {
		return "", err
	}
	return k.key, nil
}

func (m *SessionManager) ExchangeKey(key string) (string, error) {
	return m.keys.Pop(key)
}

func (m *SessionManager) getSessionInState(sessionID string, state sessionState) (*Session, error) {
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
	s, err := m.getSessionInState(sessionID, sessionStateNew)
	if err != nil {
		return nil, err
	}

	s.Identity = ident
	s.State = sessionStateIdentified

	if err = m.sessions.Set(*s); err != nil {
		return nil, err
	}

	return s, nil
}

func (m *SessionManager) Kill(sessionID string) (*Session, error) {
	s, err := m.sessions.Get(sessionID)
	if err != nil {
		return nil, err
	}

	s.State = sessionStateDead

	if err = m.sessions.Set(*s); err != nil {
		return nil, err
	}

	return s, nil
}
