package server

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/session"
)

type StaticKeyManager struct {
	key.PrivateKeyManager
	expiresAt time.Time
	signer    josesig.Signer
	keys      []jose.JWK
}

func (m *StaticKeyManager) ExpiresAt() time.Time {
	return m.expiresAt
}

func (m *StaticKeyManager) Signer() (josesig.Signer, error) {
	return m.signer, nil
}

func (m *StaticKeyManager) JWKs() ([]jose.JWK, error) {
	return m.keys, nil
}

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
	return func() (string, error) {
		return code, nil
	}
}

func TestServerProviderConfig(t *testing.T) {
	srv := &Server{IssuerURL: url.URL{Scheme: "http", Host: "server.example.com"}}

	want := oidc.ProviderConfig{
		Issuer:                            "http://server.example.com",
		AuthEndpoint:                      "http://server.example.com/auth",
		TokenEndpoint:                     "http://server.example.com/token",
		KeysEndpoint:                      "http://server.example.com/keys",
		GrantTypesSupported:               []string{oauth2.GrantTypeAuthCode, oauth2.GrantTypeClientCreds},
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
	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	srv := &Server{
		SessionManager: sm,
	}

	state := "pants"
	ci := oidc.ClientIdentity{
		Credentials: oauth2.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
		Metadata: oidc.ClientMetadata{
			RedirectURL: url.URL{
				Scheme: "http",
				Host:   "client.example.com",
				Path:   "/callback",
			},
		},
	}

	key, err := srv.NewSession(ci.Credentials.ID, state, ci.Metadata.RedirectURL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sessionID, err := sm.ExchangeKey(key)
	if err != nil {
		t.Fatalf("Session not retreivable: %v", err)
	}

	ses, err := sm.Identify(sessionID, oidc.Identity{})
	if err != nil {
		t.Fatalf("Unable to add Identity to Session: %v", err)
	}

	if !reflect.DeepEqual(ci.Metadata.RedirectURL, ses.RedirectURL) {
		t.Fatalf("Session created with incorrect RedirectURL: want=%#v got=%#v", ci.Metadata.RedirectURL, ses.RedirectURL)
	}

	if ci.Credentials.ID != ses.ClientID {
		t.Fatalf("Session created with incorrect ClientID: want=%q got=%q", ci.Credentials.ID, ses.ClientID)
	}

	if state != ses.ClientState {
		t.Fatalf("Session created with incorrect State: want=%q got=%q", state, ses.ClientState)
	}
}

func TestServerLogin(t *testing.T) {
	ci := oidc.ClientIdentity{
		Credentials: oauth2.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
		Metadata: oidc.ClientMetadata{
			RedirectURL: url.URL{
				Scheme: "http",
				Host:   "client.example.com",
				Path:   "/callback",
			},
		},
	}
	ciRepo := NewClientIdentityRepo([]oidc.ClientIdentity{ci})

	km := &StaticKeyManager{
		signer: &StaticSigner{sig: []byte("beer"), err: nil},
	}

	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	sm.GenerateCode = staticGenerateCodeFunc("fakecode")
	sessionID, err := sm.NewSession(ci.Credentials.ID, "bogus", ci.Metadata.RedirectURL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	srv := &Server{
		IssuerURL:          url.URL{Scheme: "http", Host: "server.example.com"},
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	ident := oidc.Identity{ID: "YYY", Name: "elroy", Email: "elroy@example.com"}
	key, err := sm.NewSessionKey(sessionID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	redirectURL, err := srv.Login(ident, key)
	if err != nil {
		t.Fatalf("Unexpected err from Server.Login: %v", err)
	}

	wantRedirectURL := "http://client.example.com/callback?code=fakecode&state=bogus"
	if wantRedirectURL != redirectURL {
		t.Fatalf("Unexpected redirectURL: want=%q, got=%q", wantRedirectURL, redirectURL)
	}
}

func TestServerLoginUnrecognizedSessionKey(t *testing.T) {
	ciRepo := NewClientIdentityRepo([]oidc.ClientIdentity{
		oidc.ClientIdentity{
			Credentials: oauth2.ClientCredentials{
				ID: "XXX", Secret: "secrete",
			},
		},
	})
	km := &StaticKeyManager{
		signer: &StaticSigner{sig: nil, err: errors.New("fail")},
	}
	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	srv := &Server{
		IssuerURL:          url.URL{Scheme: "http", Host: "server.example.com"},
		KeyManager:         km,
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

func TestServerCodeToken(t *testing.T) {
	ci := oidc.ClientIdentity{
		Credentials: oauth2.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
	}
	ciRepo := NewClientIdentityRepo([]oidc.ClientIdentity{ci})
	km := &StaticKeyManager{
		signer: &StaticSigner{sig: []byte("beer"), err: nil},
	}
	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())

	srv := &Server{
		IssuerURL:          url.URL{Scheme: "http", Host: "server.example.com"},
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	sessionID, err := sm.NewSession(ci.Credentials.ID, "bogus", url.URL{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, err = sm.Identify(sessionID, oidc.Identity{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	key, err := sm.NewSessionKey(sessionID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jwt, err := srv.CodeToken(ci.Credentials, key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if jwt == nil {
		t.Fatalf("Expected non-nil jwt")
	}
}

func TestServerTokenUnrecognizedKey(t *testing.T) {
	ci := oidc.ClientIdentity{
		Credentials: oauth2.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
	}
	ciRepo := NewClientIdentityRepo([]oidc.ClientIdentity{ci})
	km := &StaticKeyManager{
		signer: &StaticSigner{sig: []byte("beer"), err: nil},
	}
	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())

	srv := &Server{
		IssuerURL:          url.URL{Scheme: "http", Host: "server.example.com"},
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}

	sessionID, err := sm.NewSession(ci.Credentials.ID, "bogus", url.URL{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = sm.Identify(sessionID, oidc.Identity{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jwt, err := srv.CodeToken(ci.Credentials, "foo")
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
	if jwt != nil {
		t.Fatalf("Expected nil jwt")
	}
}

func TestServerTokenFail(t *testing.T) {
	issuerURL := url.URL{Scheme: "http", Host: "server.example.com"}
	keyFixture := "goodkey"
	ccFixture := oauth2.ClientCredentials{
		ID:     "XXX",
		Secret: "secrete",
	}
	signerFixture := &StaticSigner{sig: []byte("beer"), err: nil}

	tests := []struct {
		signer josesig.Signer
		argCC  oauth2.ClientCredentials
		argKey string
		err    string
	}{
		// control test case to make sure fixtures check out
		{
			signer: signerFixture,
			argCC:  ccFixture,
			argKey: keyFixture,
		},

		// unrecognized key
		{
			signer: signerFixture,
			argCC:  ccFixture,
			argKey: "foo",
			err:    oauth2.ErrorInvalidGrant,
		},

		// unrecognized client
		{
			signer: signerFixture,
			argCC:  oauth2.ClientCredentials{ID: "YYY"},
			argKey: keyFixture,
			err:    oauth2.ErrorInvalidClient,
		},

		// signing operation fails
		{
			signer: &StaticSigner{sig: nil, err: errors.New("fail")},
			argCC:  ccFixture,
			argKey: keyFixture,
			err:    oauth2.ErrorServerError,
		},
	}

	for i, tt := range tests {
		sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
		sm.GenerateCode = func() (string, error) { return keyFixture, nil }

		sessionID, err := sm.NewSession(ccFixture.ID, "bogus", url.URL{})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		_, err = sm.Identify(sessionID, oidc.Identity{})
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}
		km := &StaticKeyManager{
			signer: tt.signer,
		}
		ciRepo := NewClientIdentityRepo([]oidc.ClientIdentity{
			oidc.ClientIdentity{Credentials: ccFixture},
		})
		srv := &Server{
			IssuerURL:          issuerURL,
			KeyManager:         km,
			SessionManager:     sm,
			ClientIdentityRepo: ciRepo,
		}

		_, err = sm.NewSessionKey(sessionID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		jwt, err := srv.CodeToken(tt.argCC, tt.argKey)
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
