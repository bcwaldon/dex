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
	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.generateCode = staticGenerateCodeFunc("fakecode")
	sm.clock = clockwork.NewFakeClock()

	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

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

	jwt, err := josesig.NewSignedJWT(claims, signer)
	if err != nil {
		t.Fatalf("Failed creating signed JWT: %v", err)
	}

	want := &Session{
		State:          SessionStateNew,
		AuthCode:       "fakecode",
		ExpiresAt:      now.Add(10 * time.Minute),
		ClientIdentity: ci,
		IDToken:        *jwt,
	}
	got, err := sm.NewSession(ci, ident)
	if err != nil {
		t.Fatalf("Failed creating NewSession: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("Incorrect Session: want=%#v got=%#v", want, got)
	}
}

func TestSessionManagerExchangeSession(t *testing.T) {
	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.clock = clockwork.NewFakeClock()

	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

	ses1, err := sm.NewSession(ci, ident)
	if err != nil {
		t.Fatalf("Failed creating NewSession: %v", err)
	}
	if ses1 == nil {
		t.Fatalf("Created nil Session")
	}

	ses2 := sm.Exchange(ci, ses1.AuthCode)
	if !reflect.DeepEqual(ses1, ses2) {
		t.Fatalf("Session mismatch: want=%#v got=%#v", ses1, ses2)
	}
}

func TestSessionManagerExchangeSessionAgain(t *testing.T) {
	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.clock = clockwork.NewFakeClock()

	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

	ses1, err := sm.NewSession(ci, ident)
	if err != nil {
		t.Fatalf("Failed creating NewSession: %v", err)
	}
	if ses1 == nil {
		t.Fatalf("Created nil Session")
	}

	ses2 := sm.Exchange(ci, ses1.AuthCode)
	if ses2 == nil {
		t.Fatalf("Expected non-nil Session, got=%#v", ses2)
	}

	ses3 := sm.Exchange(ci, ses1.AuthCode)
	if ses3 != nil {
		t.Fatalf("Expected nil Session, got %#v", ses3)
	}
}

func TestSessionManagerExchangeSessionExpired(t *testing.T) {
	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	fc := clockwork.NewFakeClock()
	sm.clock = fc

	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}

	ses1, err := sm.NewSession(ci, ident)
	if err != nil {
		t.Fatalf("Failed creating NewSession: %v", err)
	}
	if ses1 == nil {
		t.Fatalf("Created nil Session")
	}

	fc.Advance(authCodeValidityWindow + time.Second)

	ses2 := sm.Exchange(ci, ses1.AuthCode)
	if ses2 != nil {
		t.Fatalf("Expected nil Session, got %#v", ses2)
	}
}
