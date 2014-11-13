package server

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

type StaticSigner struct {
	sig []byte
	err error
}

func (ss *StaticSigner) ID() string {
	return "static"
}

func (ss *StaticSigner) Alg() string {
	return "static"
}

func (ss *StaticSigner) Verify(sig, data []byte) error {
	if !reflect.DeepEqual(ss.sig, sig) {
		return errors.New("signature mismatch")
	}

	return nil
}

func (ss *StaticSigner) Sign(data []byte) ([]byte, error) {
	return ss.sig, ss.err
}

func (ss *StaticSigner) JWK() jose.JWK {
	return jose.JWK{}
}

func staticGenerateCodeFunc(code string) generateCodeFunc {
	return func() string {
		return code
	}
}

func TestSessionManagerNewSession(t *testing.T) {
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	sm := NewSessionManager("http://server.example.com", nil)
	fc := clockwork.NewFakeClock()
	sm.clock = fc

	want := &Session{
		State:          sessionStateNew,
		ClientIdentity: ci,
		ClientState:    "bogus",
		CreatedAt:      fc.Now().UTC(),
		sessionManager: sm,
	}

	got := sm.NewSession(ci, "bogus")
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("Incorrect Session: want=%#v got=%#v", want, got)
	}
}

func TestSessionIdentifyTwice(t *testing.T) {
	sm := NewSessionManager("http://server.example.com", nil)
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

	ses := sm.NewSession(ci, "bogus")

	if err := ses.Identify(ident); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if err := ses.Identify(ident); err == nil {
		t.Fatalf("Expected non-nil error")
	}
}

func TestSessionIDToken(t *testing.T) {
	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.generateCode = staticGenerateCodeFunc("fakecode")
	sm.clock = clockwork.NewFakeClock()

	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}
	ses := sm.NewSession(ci, "bogus")
	if err := ses.Identify(ident); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	now := sm.clock.Now().UTC()
	claims := jose.Claims{
		// required
		"iss": "http://server.example.com",
		"sub": "YYY",
		"aud": "XXX",
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(time.Hour).Unix()),

		// conventional
		"name":  "elroy",
		"email": "elroy@example.com",
	}

	want, err := josesig.NewSignedJWT(claims, signer)
	if err != nil {
		t.Fatalf("Failed creating signed JWT: %v", err)
	}

	got, err := ses.IDToken()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("Incorrect JWT: want=%#v got=%#v", want, got)
	}
}

func TestSessionIDTokenSignerFails(t *testing.T) {
	signer := &StaticSigner{sig: nil, err: errors.New("failed")}
	sm := NewSessionManager("http://server.example.com", signer)

	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

	ses := sm.NewSession(ci, "bogus")
	if err := ses.Identify(ident); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err := ses.IDToken(); err == nil {
		t.Fatalf("Expected non-nil error")
	}
}

func TestSessionManagerLookup(t *testing.T) {
	signer := &StaticSigner{sig: []byte("beer"), err: nil}
	sm := NewSessionManager("http://server.example.com", signer)

	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ses := sm.NewSession(ci, "bogus")
	key := ses.NewKey()

	got := sm.Session(key)
	if !reflect.DeepEqual(ses, got) {
		t.Fatalf("Incorrect Session: want=%#v got=%#v", ses, got)
	}

	again := sm.Session(key)
	if again != nil {
		t.Fatalf("Received non-nil response from second attempt with session key")
	}
}
