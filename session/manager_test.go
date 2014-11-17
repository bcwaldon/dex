package session

import (
	"testing"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

func staticGenerateCodeFunc(code string) GenerateCodeFunc {
	return func() string {
		return code
	}
}

func TestSessionManagerNewSession(t *testing.T) {
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	sm := NewSessionManager()
	sm.GenerateCode = staticGenerateCodeFunc("boo")

	got, err := sm.NewSession(ci, "bogus")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != "boo" {
		t.Fatalf("Incorrect Session ID: want=%s got=%s", "boo", got)
	}
}

func TestSessionIdentifyTwice(t *testing.T) {
	sm := NewSessionManager()
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

	sessionID, err := sm.NewSession(ci, "bogus")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err := sm.Identify(sessionID, ident); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err := sm.Identify(sessionID, ident); err == nil {
		t.Fatalf("Expected non-nil error")
	}
}

func TestSessionManagerExchangeKey(t *testing.T) {
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	sm := NewSessionManager()

	sessionID, err := sm.NewSession(ci, "bogus")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	key, err := sm.NewSessionKey(sessionID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	got, err := sm.ExchangeKey(key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if got != sessionID {
		t.Fatalf("Incorrect Session ID: want=%s got=%s", sessionID, got)
	}

	if _, err := sm.ExchangeKey(key); err == nil {
		t.Fatalf("Received nil response from attempt with spent Session key")
	}
}

func TestSessionManagerGetSessionInStateNoExist(t *testing.T) {
	sm := NewSessionManager()
	ses, err := sm.getSessionInState("123", sessionStateNew)
	if err == nil {
		t.Errorf("Expected non-nil error")
	}
	if ses != nil {
		t.Errorf("Expected nil Session")
	}
}

func TestSessionManagerGetSessionInStateWrongState(t *testing.T) {
	sm := NewSessionManager()
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	sessionID, err := sm.NewSession(ci, "bogus")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	ses, err := sm.getSessionInState(sessionID, sessionStateDead)
	if err == nil {
		t.Errorf("Expected non-nil error")
	}
	if ses != nil {
		t.Errorf("Expected nil Session")
	}
}

func TestSessionManagerKill(t *testing.T) {
	sm := NewSessionManager()
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

	sessionID, err := sm.NewSession(ci, "bogus")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err := sm.Identify(sessionID, ident); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	ses, err := sm.Kill(sessionID)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if ses == nil {
		t.Fatalf("Expected non-nil Session")
	}

	if ses.ClientState != "bogus" {
		t.Errorf("Unexpected Session: %#v", ses)
	}
}

func TestSessionManagerKillUnidentified(t *testing.T) {
	sm := NewSessionManager()
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}

	sessionID, err := sm.NewSession(ci, "bogus")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, err = sm.Kill(sessionID)
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
}
