package functional

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/coopernurse/gorp"

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

func connect(t *testing.T) *gorp.DbMap {
	c, err := db.NewConnection(db.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("Unable to connect to database: %v", err)
	}

	if err = c.DropTablesIfExists(); err != nil {
		t.Fatalf("Unable to drop database tables: %v", err)
	}

	if err = c.CreateTablesIfNotExists(); err != nil {
		t.Fatalf("Unable to create database tables: %v", err)
	}

	return c
}

func TestDBSessionKeyRepoPushPop(t *testing.T) {
	r := db.NewSessionKeyRepo(connect(t))

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
	r := db.NewSessionRepo(connect(t))

	// postgres stores its time type with a lower precision
	// than we generate here. Stripping off nanoseconds gives
	// us a predictable value to use in comparisions.
	now := time.Now().Round(time.Second).UTC()

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
			ID:        "YYY",
			Name:      "Elroy",
			Email:     "elroy@example.com",
			ExpiresAt: now.Add(time.Minute),
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
	r, err := db.NewPrivateKeySetRepo(connect(t), "roflroflroflroflroflroflroflrofl")
	if err != nil {
		t.Fatalf(err.Error())
	}

	k1, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}

	k2, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}

	ks := key.NewPrivateKeySet([]*key.PrivateKey{k1, k2}, time.Now().Add(time.Minute))
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

func TestDBClientIdentityRepoMetadata(t *testing.T) {
	r := db.NewClientIdentityRepo(connect(t))

	cm := oidc.ClientMetadata{
		RedirectURLs: []url.URL{
			url.URL{Scheme: "http", Host: "127.0.0.1:5556", Path: "/cb"},
			url.URL{Scheme: "https", Host: "example.com", Path: "/callback"},
		},
	}

	_, err := r.New("foo", cm)
	if err != nil {
		t.Fatalf(err.Error())
	}

	got, err := r.Metadata("foo")
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !reflect.DeepEqual(cm, *got) {
		t.Fatalf("Retrieved incorrect ClientMetadata: want=%#v got=%#v", cm, *got)
	}
}

func TestDBClientIdentityRepoMetadataNoExist(t *testing.T) {
	r := db.NewClientIdentityRepo(connect(t))

	got, err := r.Metadata("noexist")
	if err != nil {
		t.Fatalf(err.Error())
	}
	if got != nil {
		t.Fatalf("Retrieved incorrect ClientMetadata: want=nil got=%#v", got)
	}
}

func TestDBClientIdentityRepoNewDuplicate(t *testing.T) {
	r := db.NewClientIdentityRepo(connect(t))

	meta1 := oidc.ClientMetadata{
		RedirectURLs: []url.URL{
			url.URL{Scheme: "http", Host: "foo.example.com"},
		},
	}

	if _, err := r.New("foo", meta1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta2 := oidc.ClientMetadata{
		RedirectURLs: []url.URL{
			url.URL{Scheme: "http", Host: "bar.example.com"},
		},
	}

	if _, err := r.New("foo", meta2); err == nil {
		t.Fatalf("expected non-nil error")
	}
}

func TestDBClientIdentityRepoAuthenticate(t *testing.T) {
	r := db.NewClientIdentityRepo(connect(t))

	cm := oidc.ClientMetadata{
		RedirectURLs: []url.URL{
			url.URL{Scheme: "http", Host: "127.0.0.1:5556", Path: "/cb"},
		},
	}

	cc, err := r.New("baz", cm)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if cc.ID != "baz" {
		t.Fatalf("Returned ClientCredentials has incorrect ID: want=baz got=%s", cc.ID)
	}

	ok, err := r.Authenticate(*cc)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	} else if !ok {
		t.Fatalf("Authentication failed for good creds")
	}

	creds := []oidc.ClientCredentials{
		// completely made up
		oidc.ClientCredentials{ID: "foo", Secret: "bar"},

		// good client ID, bad secret
		oidc.ClientCredentials{ID: cc.ID, Secret: "bar"},

		// bad client ID, good secret
		oidc.ClientCredentials{ID: "foo", Secret: cc.Secret},

		// good client ID, secret with some fluff on the end
		oidc.ClientCredentials{ID: cc.ID, Secret: fmt.Sprintf("%sfluff", cc.Secret)},
	}
	for i, c := range creds {
		ok, err := r.Authenticate(c)
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
		} else if ok {
			t.Errorf("case %d: authentication succeeded for bad creds", i)
		}
	}
}

func TestDBClientIdentityAll(t *testing.T) {
	r := db.NewClientIdentityRepo(connect(t))

	cm := oidc.ClientMetadata{
		RedirectURLs: []url.URL{
			url.URL{Scheme: "http", Host: "127.0.0.1:5556", Path: "/cb"},
		},
	}

	_, err := r.New("foo", cm)
	if err != nil {
		t.Fatalf(err.Error())
	}

	got, err := r.All()
	if err != nil {
		t.Fatalf(err.Error())
	}
	count := len(got)
	if count != 1 {
		t.Fatalf("Retrieved incorrect number of ClientIdentities: want=1 got=%d", count)
	}

	if !reflect.DeepEqual(cm, got[0].Metadata) {
		t.Fatalf("Retrieved incorrect ClientMetadata: want=%#v got=%#v", cm, got[0])
	}

	cm = oidc.ClientMetadata{
		RedirectURLs: []url.URL{
			url.URL{Scheme: "http", Host: "foo.com", Path: "/cb"},
		},
	}
	_, err = r.New("bar", cm)
	if err != nil {
		t.Fatalf(err.Error())
	}

	got, err = r.All()
	if err != nil {
		t.Fatalf(err.Error())
	}
	count = len(got)
	if count != 2 {
		t.Fatalf("Retrieved incorrect number of ClientIdentities: want=2 got=%d", count)
	}
}
