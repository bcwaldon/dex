package server

import (
	"errors"
	"net/url"
	"reflect"
	"testing"

	josesig "github.com/coreos-inc/auth/jose/sig"
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
	ci := oauth2.ClientIdentity{
		ID:     "XXX",
		Secret: "secrete",
		RedirectURL: url.URL{
			Scheme: "http",
			Host:   "client.example.com",
			Path:   "/callback",
		},
	}
	ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{ci})

	signer := &StaticSigner{sig: []byte("beer"), err: nil}

	sm := NewSessionManager("http://server.example.com", signer)
	sm.generateCode = staticGenerateCodeFunc("fakecode")
	ses := sm.NewSession(ci, "bogus")

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}
	redirectURL, err := srv.Login(ident, ses.NewKey())
	if err != nil {
		t.Fatalf("Unexpected err from Server.Login: %v", err)
	}

	wantRedirectURL := "http://client.example.com/callback?code=fakecode&state=bogus"
	if wantRedirectURL != redirectURL {
		t.Fatalf("Unexpected redirectURL: want=%q, got=%q", wantRedirectURL, redirectURL)
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

func TestServerToken(t *testing.T) {
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{ci})
	signer := &StaticSigner{sig: []byte("beer"), err: nil}
	sm := NewSessionManager("http://server.example.com", signer)

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ses := sm.NewSession(ci, "bogus")
	err := ses.Identify(oidc.Identity{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jwt, err := srv.Token(ci, ses.NewKey())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if jwt == nil {
		t.Fatalf("Expected non-nil jwt")
	}
}

func TestServerTokenUnrecognizedKey(t *testing.T) {
	ci := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{ci})
	signer := &StaticSigner{sig: []byte("beer"), err: nil}
	sm := NewSessionManager("http://server.example.com", signer)

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ses := sm.NewSession(ci, "bogus")
	err := ses.Identify(oidc.Identity{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jwt, err := srv.Token(ci, "foo")
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
	if jwt != nil {
		t.Fatalf("Expected nil jwt")
	}
}

func TestServerTokenFail(t *testing.T) {
	issuerURL := "http://server.example.com"
	keyFixture := "goodkey"
	ciFixture := oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"}
	signerFixture := &StaticSigner{sig: []byte("beer"), err: nil}

	tests := []struct {
		signer josesig.Signer
		argCI  oauth2.ClientIdentity
		argKey string
		err    error
	}{
		// control test case to make sure fixtures check out
		{
			signer: signerFixture,
			argCI:  ciFixture,
			argKey: keyFixture,
		},

		// unrecognized key
		{
			signer: signerFixture,
			argCI:  ciFixture,
			argKey: "foo",
			err:    oauth2.ErrorInvalidGrant,
		},

		// unrecognized client
		{
			signer: signerFixture,
			argCI:  oauth2.ClientIdentity{ID: "YYY"},
			argKey: keyFixture,
			err:    oauth2.ErrorInvalidClient,
		},

		// signing operation fails
		{
			signer: &StaticSigner{sig: nil, err: errors.New("fail")},
			argCI:  ciFixture,
			argKey: keyFixture,
			err:    oauth2.ErrorServerError,
		},
	}

	for i, tt := range tests {
		sm := NewSessionManager("http://server.example.com", tt.signer)
		sm.generateCode = func() string { return keyFixture }

		ses := sm.NewSession(ciFixture, "bogus")
		err := ses.Identify(oidc.Identity{})
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}

		ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{ciFixture})
		srv := &Server{
			IssuerURL:          issuerURL,
			Signer:             tt.signer,
			SessionManager:     sm,
			ClientIdentityRepo: ciRepo,
		}

		// need to create the key, but no need to address it
		ses.NewKey()

		jwt, err := srv.Token(tt.argCI, tt.argKey)
		if tt.err == nil {
			if err != nil {
				t.Errorf("case %d: got non-nil error: %v", i, err)
			} else if jwt == nil {
				t.Errorf("case %d: got nil JWT", i)
			}

		} else {
			if err != tt.err {
				t.Errorf("case %d: want err %q, got %q", i, tt.err, err)
			} else if jwt != nil {
				t.Errorf("case %d: got non-nil JWT", i)
			}
		}
	}
}
