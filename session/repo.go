package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/jonboulle/clockwork"
)

type sessionRepo interface {
	Set(Session) error
	Get(string) (*Session, error)
}

type sessionKeyRepo interface {
	Push(sessionKey, time.Duration) error
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

func (m *memSessionRepo) Get(sessionID string) (*Session, error) {
	s, ok := m.store[sessionID]
	if !ok {
		return nil, fmt.Errorf("unrecognized ID")
	}
	return &s, nil
}

func (m *memSessionRepo) Set(s Session) error {
	m.store[s.ID] = s
	return nil
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

func (m *memSessionKeyRepo) Push(sk sessionKey, ttl time.Duration) error {
	m.store[sk.key] = expiringSessionKey{
		sessionKey: sk,
		expiresAt:  m.clock.Now().UTC().Add(ttl),
	}
	return nil
}
