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
	Push(SessionKey, time.Duration) error
	Pop(string) (string, error)
}

func newMemSessionRepo() sessionRepo {
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
	SessionKey
	expiresAt time.Time
}

func newMemSessionKeyRepo() sessionKeyRepo {
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

	return esk.SessionKey.SessionID, nil
}

func (m *memSessionKeyRepo) Push(sk SessionKey, ttl time.Duration) error {
	m.store[sk.Key] = expiringSessionKey{
		SessionKey: sk,
		expiresAt:  m.clock.Now().UTC().Add(ttl),
	}
	return nil
}
