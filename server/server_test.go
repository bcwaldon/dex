package server

import (
	"errors"
	"net/url"
	"reflect"
	"testing"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/session"
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

func staticGenerateCodeFunc(code string) session.GenerateCodeFunc {
	return func() string {
		return code
	}
}

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

func TestServerNewSession(t *testing.T) {
	signerFixture := &StaticSigner{sig: []byte("beer"), err: nil}
	ciFixture := oauth2.ClientIdentity{
		ID:     "XXX",
		Secret: "secrete",
		RedirectURL: url.URL{
			Scheme: "http",
			Host:   "client.example.com",
			Path:   "/callback",
		},
	}
	ciRepoFixture := NewClientIdentityRepo([]oauth2.ClientIdentity{ciFixture})

	tests := []struct {
		acr oauth2.AuthCodeRequest
		err string
	}{
		// basic request succeeds
		{
			acr: oauth2.AuthCodeRequest{
				ClientID:    "XXX",
				RedirectURL: nil,
				Scope:       []string{"foo", "bar"},
				State:       "pants",
			},
		},

		// RedirectURL provided, matching that in ClientIdentity
		{
			acr: oauth2.AuthCodeRequest{
				ClientID:    "XXX",
				RedirectURL: &ciFixture.RedirectURL,
				Scope:       []string{"foo", "bar"},
				State:       "pants",
			},
		},

		// unrecognized client
		{
			acr: oauth2.AuthCodeRequest{
				ClientID:    "YYY",
				RedirectURL: &ciFixture.RedirectURL,
				Scope:       []string{"foo", "bar"},
				State:       "pants",
			},
			err: oauth2.ErrorInvalidRequest,
		},

		// mismatched RedirectURL
		{
			acr: oauth2.AuthCodeRequest{
				ClientID:    "XXX",
				RedirectURL: &url.URL{Scheme: "http", Host: "example.com"},
				Scope:       []string{"foo", "bar"},
				State:       "pants",
			},
			err: oauth2.ErrorInvalidRequest,
		},
	}

	for i, tt := range tests {
		sm := session.NewSessionManager()
		srv := &Server{
			IssuerURL:          "http://server.example.com",
			Signer:             signerFixture,
			ClientIdentityRepo: ciRepoFixture,
			SessionManager:     sm,
		}

		key, err := srv.NewSession(tt.acr)
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("case %d: incorrect error: want=%q got=%v", i, tt.err, err)
			}
			continue
		}

		if err != nil {
			t.Errorf("case %d: got non-nil error: %v", i, err)
			continue
		}

		sessionID, err := sm.ExchangeKey(key)
		if err != nil {
			t.Errorf("case %d: session not retreivable", i)
			continue
		}

		ses, err := sm.Identify(sessionID, oidc.Identity{})
		if err != nil {
			t.Errorf("case %d: unable to add Identity to Session: %v", i, err)
			continue
		}

		if ciFixture != ses.ClientIdentity {
			t.Errorf("case %d: session created with incorrect ClientIdentity: want=%#v got=%#v", i, ciFixture, ses.ClientIdentity)
		}

		if tt.acr.State != ses.ClientState {
			t.Errorf("case %d: session created with incorrect State: want=%q got=%q", i, tt.acr.State, ses.ClientState)
		}
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

	sm := session.NewSessionManager()
	sm.GenerateCode = staticGenerateCodeFunc("fakecode")
	sessionID := sm.NewSession(ci, "bogus")

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}
	redirectURL, err := srv.Login(ident, sm.NewSessionKey(sessionID))
	if err != nil {
		t.Fatalf("Unexpected err from Server.Login: %v", err)
	}

	wantRedirectURL := "http://client.example.com/callback?code=fakecode&state=bogus"
	if wantRedirectURL != redirectURL {
		t.Fatalf("Unexpected redirectURL: want=%q, got=%q", wantRedirectURL, redirectURL)
	}
}

func TestServerLoginUnrecognizedSessionKey(t *testing.T) {
	ciRepo := NewClientIdentityRepo([]oauth2.ClientIdentity{
		oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"},
	})
	signer := &StaticSigner{sig: nil, err: errors.New("fail")}
	sm := session.NewSessionManager()
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
	sm := session.NewSessionManager()

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	sessionID := sm.NewSession(ci, "bogus")
	_, err := sm.Identify(sessionID, oidc.Identity{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jwt, err := srv.Token(ci, sm.NewSessionKey(sessionID))
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
	sm := session.NewSessionManager()

	srv := &Server{
		IssuerURL:          "http://server.example.com",
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	sessionID := sm.NewSession(ci, "bogus")
	_, err := sm.Identify(sessionID, oidc.Identity{})
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
		err    string
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
		sm := session.NewSessionManager()
		sm.GenerateCode = func() string { return keyFixture }

		sessionID := sm.NewSession(ciFixture, "bogus")
		_, err := sm.Identify(sessionID, oidc.Identity{})
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
		sm.NewSessionKey(sessionID)

		jwt, err := srv.Token(tt.argCI, tt.argKey)
		if tt.err == "" {
			if err != nil {
				t.Errorf("case %d: got non-nil error: %v", i, err)
			} else if jwt == nil {
				t.Errorf("case %d: got nil JWT", i)
			}

		} else {
			if err.Error() != tt.err {
				t.Errorf("case %d: want err %q, got %q", i, tt.err, err.Error())
			} else if jwt != nil {
				t.Errorf("case %d: got non-nil JWT", i)
			}
		}
	}
}
