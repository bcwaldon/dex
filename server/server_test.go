package server

import (
	"errors"
	"reflect"
	"testing"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

func TestServerProviderConfig(t *testing.T) {
	srv := &Server{IssuerURL: "http://server.example.com"}

	want := oidc.ProviderConfig{
		Issuer:                            "http://server.example.com",
		AuthEndpoint:                      "http://server.example.com/auth",
		TokenEndpoint:                     "http://server.example.com/token",
		KeysEndpoint:                      "http://server.example.com/keys",
		GrantTypesSupported:               []string{"authorization_code"},
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenAlgValuesSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}
	got := srv.ProviderConfig()

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("want=%#v, got=%#v", want, got)
	}
}

func TestServerLogin(t *testing.T) {
	ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{
		oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"},
	})

	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.generateCode = staticGenerateCodeFunc("fakecode")

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}
	code, err := srv.Login(ident, "XXX")
	if err != nil {
		t.Fatalf("Unexpected err from Server.Login: %v", err)
	}

	if code != "fakecode" {
		t.Fatalf("Expected code=fakecode, got=%s", code)
	}
}

func TestServerLoginUnrecognizedClient(t *testing.T) {
	ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{
		oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"},
	})

	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.generateCode = staticGenerateCodeFunc("fakecode")

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}
	code, err := srv.Login(ident, "123")
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}

	if code != "" {
		t.Fatalf("Expected empty code, got=%s", code)
	}
}

func TestServerLoginNewSessionFails(t *testing.T) {
	ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{
		oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"},
	})

	signer := &StaticSigner{sig: nil, err: errors.New("fail")}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.generateCode = staticGenerateCodeFunc("fakecode")

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}
	code, err := srv.Login(ident, "XXX")
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}

	if code != "" {
		t.Fatalf("Expected empty code, got=%s", code)
	}
}