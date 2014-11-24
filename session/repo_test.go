package session

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func TestMemSessionKeyRepoPopNoExist(t *testing.T) {
	r := &memSessionKeyRepo{
		store: make(map[string]expiringSessionKey),
		clock: clockwork.NewFakeClock(),
	}

	_, err := r.Pop("123")
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestMemSessionKeyRepoPushPop(t *testing.T) {
	r := &memSessionKeyRepo{
		store: make(map[string]expiringSessionKey),
		clock: clockwork.NewFakeClock(),
	}

	key := "123"
	sessionID := "456"

	r.Push(SessionKey{Key: key, SessionID: sessionID}, time.Second)

	got, err := r.Pop(key)
	if err != nil {
		t.Fatalf("Expected nil error: %v", err)
	}

	if got != sessionID {
		t.Fatalf("Incorrect sessionID: want=%s got=%s", sessionID, got)
	}
}

func TestMemSessionKeyRepoExpired(t *testing.T) {
	fc := clockwork.NewFakeClock()
	r := &memSessionKeyRepo{
		store: make(map[string]expiringSessionKey),
		clock: fc,
	}

	key := "123"
	sessionID := "456"

	r.Push(SessionKey{Key: key, SessionID: sessionID}, time.Second)

	fc.Advance(2 * time.Second)

	_, err := r.Pop(key)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestMemSessionRepoGetNoExist(t *testing.T) {
	r := &memSessionRepo{
		store: make(map[string]Session),
	}

	ses, err := r.Get("123")
	if ses != nil {
		t.Fatalf("Expected nil, got %#v", ses)
	}
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
}

func TestMemSessionRepoCreateGet(t *testing.T) {
	fc := clockwork.NewFakeClock()
	r := &memSessionRepo{
		store: make(map[string]Session),
		clock: fc,
	}

	r.Create(Session{
		ID:          "123",
		ClientState: "blargh",
		ExpiresAt:   fc.Now().UTC().Add(time.Minute),
	})

	ses, _ := r.Get("123")
	if ses == nil {
		t.Fatalf("Expected non-nil Session")
	}

	if ses.ClientState != "blargh" {
		t.Fatalf("Session unrecognized")
	}
}

func TestMemSessionRepoCreateUpdate(t *testing.T) {
	fc := clockwork.NewFakeClock()
	r := &memSessionRepo{
		store: make(map[string]Session),
		clock: fc,
	}

	r.Create(Session{
		ID:          "123",
		ClientState: "blargh",
		ExpiresAt:   fc.Now().UTC().Add(time.Minute),
	})
	r.Update(Session{
		ID:          "123",
		ClientState: "boom",
		ExpiresAt:   fc.Now().UTC().Add(time.Minute),
	})

	ses, _ := r.Get("123")
	if ses == nil {
		t.Fatalf("Expected non-nil Session")
	}

	if ses.ClientState != "boom" {
		t.Fatalf("Session unrecognized")
	}
}

func TestMemSessionRepoUpdateNoExist(t *testing.T) {
	r := &memSessionRepo{
		store: make(map[string]Session),
	}

	err := r.Update(Session{ID: "123", ClientState: "boom"})
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
}
