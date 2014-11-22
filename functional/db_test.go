package functional

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/coreos-inc/auth/oidc"
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

func TestDBSessionKeyRepoPushPop(t *testing.T) {
	r, err := session.NewDBSessionKeyRepo(dsn)
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

func TestDBSessionRepoCreateUpdate(t *testing.T) {
	r, err := session.NewDBSessionRepo(dsn)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ses := session.Session{
		ID:          "AAA",
		State:       session.SessionStateIdentified,
		CreatedAt:   time.Date(2014, time.November, 21, 12, 14, 34, 0, time.UTC),
		ClientID:    "ZZZ",
		ClientState: "foo",
		RedirectURL: url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/callback",
		},
		Identity: oidc.Identity{
			ID:    "YYY",
			Name:  "Elroy",
			Email: "elroy@example.com",
		},
	}

	if err := r.Create(ses); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	got, err := r.Get(ses.ID)
	if err != nil {
		t.Fatalf("Unexpected error: %v")
	}

	if !reflect.DeepEqual(ses, *got) {
		t.Fatalf("Retrieved incorrect Session: want=%#v got=%#v", ses, *got)
	}
}
