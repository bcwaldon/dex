package session

import (
	"errors"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/pkg/health"
)

type SessionRepo interface {
	health.Checkable
	Get(string) (*Session, error)
	Create(Session) error
	Update(Session) error
}

type SessionKeyRepo interface {
	health.Checkable
	Push(SessionKey, time.Duration) error
	Pop(string) (string, error)
}

func NewSessionRepo() SessionRepo {
	return &memSessionRepo{
		store: make(map[string]Session),
		clock: clockwork.NewRealClock(),
	}
}

type memSessionRepo struct {
	store map[string]Session
	clock clockwork.Clock
}

func (m *memSessionRepo) Healthy() error {
	return nil
}

func (m *memSessionRepo) Get(sessionID string) (*Session, error) {
	s, ok := m.store[sessionID]
	if !ok || s.ExpiresAt.Before(m.clock.Now().UTC()) {
		return nil, errors.New("unrecognized ID")
	}
	return &s, nil
}

func (m *memSessionRepo) Create(s Session) error {
	if _, ok := m.store[s.ID]; ok {
		return errors.New("ID exists")
	}

	m.store[s.ID] = s
	return nil
}

func (m *memSessionRepo) Update(s Session) error {
	if _, ok := m.store[s.ID]; !ok {
		return errors.New("unrecognized ID")
	}
	m.store[s.ID] = s
	return nil
}

type expiringSessionKey struct {
	SessionKey
	expiresAt time.Time
}

func NewSessionKeyRepo() SessionKeyRepo {
	return &memSessionKeyRepo{
		store: make(map[string]expiringSessionKey),
		clock: clockwork.NewRealClock(),
	}
}

type memSessionKeyRepo struct {
	store map[string]expiringSessionKey
	clock clockwork.Clock
}

func (m *memSessionKeyRepo) Healthy() error {
	return nil
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
