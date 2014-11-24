package functional

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/key"
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
	r, err := db.NewSessionKeyRepo(dsn)
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
	r, err := db.NewSessionRepo(dsn)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// postgres stores its time type with a lower precision
	// than we generate here. Stripping off nanoseconds gives
	// us a predictable value to use in comparisions.
	now := time.Unix(time.Now().Unix(), 0).UTC()

	ses := session.Session{
		ID:          "AAA",
		State:       session.SessionStateIdentified,
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Minute),
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
		t.Fatalf("Unexpected error: %v", err)
	}

	if !reflect.DeepEqual(ses, *got) {
		t.Fatalf("Retrieved incorrect Session: want=%#v got=%#v", ses, *got)
	}
}

func TestDBPrivateKeySetRepoSetGet(t *testing.T) {
	r, err := db.NewPrivateKeySetRepo(dsn, "super secret key")
	if err != nil {
		t.Fatalf(err.Error())
	}

	k1, err := key.GeneratePrivateRSAKey()
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}

	k2, err := key.GeneratePrivateRSAKey()
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}

	ks := key.NewPrivateKeySet([]key.PrivateKey{k1, k2}, time.Now().Add(time.Minute))
	if err := r.Set(ks); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	got, err := r.Get()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !reflect.DeepEqual(ks, got) {
		t.Fatalf("Retrieved incorrect KeySet: want=%#v got=%#v", ks, got)
	}
}
