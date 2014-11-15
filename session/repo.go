package session

import (
	"errors"
	"time"

	"github.com/jonboulle/clockwork"
)

type sessionRepo interface {
	Set(Session)
	Get(string) *Session
}

type sessionKeyRepo interface {
	Push(sessionKey, time.Duration)
	Pop(string) (string, error)
}

func newSessionRepo() sessionRepo {
	return &memSessionRepo{
		store: make(map[string]Session),
	}
}

type memSessionRepo struct {
	store map[string]Session
}

func (m *memSessionRepo) Get(sessionID string) *Session {
	s, ok := m.store[sessionID]
	if !ok {
		return nil
	}
	return &s
}

func (m *memSessionRepo) Set(s Session) {
	m.store[s.ID] = s
}

type expiringSessionKey struct {
	sessionKey
	expiresAt time.Time
}

func newSessionKeyRepo() sessionKeyRepo {
	return &memSessionKeyRepo{
		store: make(map[string]expiringSessionKey),
		clock: clockwork.NewRealClock(),
	}
}

type memSessionKeyRepo struct {
	store map[string]expiringSessionKey
	clock clockwork.Clock
}

func (m *memSessionKeyRepo) Pop(key string) (string, error) {
	esk, ok := m.store[key]
	if !ok {
		return "", errors.New("unrecognized key")
	}
	defer delete(m.store, key)

	if esk.expiresAt.Before(m.clock.Now().UTC()) {
		return "", errors.New("expired key")
	}

	return esk.sessionKey.sessionID, nil
}

func (m *memSessionKeyRepo) Push(sk sessionKey, exp time.Duration) {
	m.store[sk.key] = expiringSessionKey{
		sessionKey: sk,
		expiresAt:  m.clock.Now().UTC().Add(exp),
	}
}
