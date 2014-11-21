package functional

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/coreos-inc/auth/session"
)

var (
	dsn string
)

func init() {
	dsn = os.Getenv("AUTHD_TEST_DSN")
	if dsn == "" {
		fmt.Println("Unable to proceed with empty env var AUTHD_TEST_DSN")
		os.Exit(1)
	}
}

func repo() (*session.DBSessionKeyRepo, error) {
	r, err := session.NewDBSessionKeyRepo(dsn)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func TestDBSessionKeyRepoPushPop(t *testing.T) {
	r, err := repo()
	if err != nil {
		t.Fatalf(err.Error())
	}

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

	// attempting to Pop a second time must fail
	if _, err := r.Pop(key); err == nil {
		t.Fatalf("Second call to Pop succeeded, expected non-nil error")
	}
}
