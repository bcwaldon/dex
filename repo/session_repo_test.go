package repo

import (
	"os"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/session"
)

var makeTestSessionRepo func() (session.SessionRepo, clockwork.FakeClock)
var makeTestSessionKeyRepo func() (session.SessionKeyRepo, clockwork.FakeClock)

func init() {
	dsn := os.Getenv("AUTHD_TEST_DSN")
	if dsn == "" {
		makeTestSessionRepo = makeTestSessionRepoMem
		makeTestSessionKeyRepo = makeTestSessionKeyRepoMem
	} else {
		makeTestSessionRepo = makeTestSessionRepoDB(dsn)
		makeTestSessionKeyRepo = makeTestSessionKeyRepoDB(dsn)
	}
}

func makeTestSessionRepoMem() (session.SessionRepo, clockwork.FakeClock) {
	fc := clockwork.NewFakeClock()
	return session.NewSessionRepoWithClock(fc), fc
}

func makeTestSessionRepoDB(dsn string) func() (session.SessionRepo, clockwork.FakeClock) {
	return func() (session.SessionRepo, clockwork.FakeClock) {
		c := initDB(dsn)
		fc := clockwork.NewFakeClock()
		return db.NewSessionRepoWithClock(c, fc), fc
	}
}

func makeTestSessionKeyRepoMem() (session.SessionKeyRepo, clockwork.FakeClock) {
	fc := clockwork.NewFakeClock()
	return session.NewSessionKeyRepoWithClock(fc), fc
}

func makeTestSessionKeyRepoDB(dsn string) func() (session.SessionKeyRepo, clockwork.FakeClock) {
	return func() (session.SessionKeyRepo, clockwork.FakeClock) {
		c := initDB(dsn)
		fc := clockwork.NewFakeClock()
		return db.NewSessionKeyRepoWithClock(c, fc), fc
	}
}

func TestSessionKeyRepoPopNoExist(t *testing.T) {
	r, _ := makeTestSessionKeyRepo()

	_, err := r.Pop("123")
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestSessionKeyRepoPushPop(t *testing.T) {
	r, _ := makeTestSessionKeyRepo()

	key := "123"
	sessionID := "456"

	r.Push(session.SessionKey{Key: key, SessionID: sessionID}, time.Second)

	got, err := r.Pop(key)
	if err != nil {
		t.Fatalf("Expected nil error: %v", err)
	}

	if got != sessionID {
		t.Fatalf("Incorrect sessionID: want=%s got=%s", sessionID, got)
	}
}

func TestSessionKeyRepoExpired(t *testing.T) {
	r, fc := makeTestSessionKeyRepo()

	key := "123"
	sessionID := "456"

	r.Push(session.SessionKey{Key: key, SessionID: sessionID}, time.Second)

	fc.Advance(2 * time.Second)

	_, err := r.Pop(key)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestSessionRepoGetNoExist(t *testing.T) {
	r, _ := makeTestSessionRepo()

	ses, err := r.Get("123")
	if ses != nil {
		t.Fatalf("Expected nil, got %#v", ses)
	}
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
}

func TestSessionRepoCreateGet(t *testing.T) {
	r, fc := makeTestSessionRepo()

	r.Create(session.Session{
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

func TestSessionRepoCreateUpdate(t *testing.T) {
	r, fc := makeTestSessionRepo()

	r.Create(session.Session{
		ID:          "123",
		ClientState: "blargh",
		ExpiresAt:   fc.Now().UTC().Add(time.Minute),
	})
	r.Update(session.Session{
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

func TestSessionRepoUpdateNoExist(t *testing.T) {
	r, _ := makeTestSessionRepo()

	err := r.Update(session.Session{ID: "123", ClientState: "boom"})
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
}
