package server

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/coreos-inc/auth/client"
	"github.com/coreos-inc/auth/refresh/refreshtest"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
)

type StaticKeyManager struct {
	key.PrivateKeyManager
	expiresAt time.Time
	signer    jose.Signer
	keys      []jose.JWK
}

func (m *StaticKeyManager) ExpiresAt() time.Time {
	return m.expiresAt
}

func (m *StaticKeyManager) Signer() (jose.Signer, error) {
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

func makeNewUserRepo() (user.UserRepo, error) {
	userRepo := user.NewUserRepo()

	id := "testid-1"
	err := userRepo.Create(nil, user.User{
		ID:    id,
		Email: "testname@example.com",
	})
	if err != nil {
		return nil, err
	}

	err = userRepo.AddRemoteIdentity(nil, id, user.RemoteIdentity{
		ConnectorID: "test_connector_id",
		ID:          "YYY",
	})
	if err != nil {
		return nil, err
	}

	return userRepo, nil
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
	nonce := "oncenay"
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
		Metadata: oidc.ClientMetadata{
			RedirectURLs: []url.URL{
				url.URL{
					Scheme: "http",
					Host:   "client.example.com",
					Path:   "/callback",
				},
			},
		},
	}

	key, err := srv.NewSession("bogus_idpc", ci.Credentials.ID, state, ci.Metadata.RedirectURLs[0], nonce, false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sessionID, err := sm.ExchangeKey(key)
	if err != nil {
		t.Fatalf("Session not retreivable: %v", err)
	}

	ses, err := sm.AttachRemoteIdentity(sessionID, oidc.Identity{})
	if err != nil {
		t.Fatalf("Unable to add Identity to Session: %v", err)
	}

	if !reflect.DeepEqual(ci.Metadata.RedirectURLs[0], ses.RedirectURL) {
		t.Fatalf("Session created with incorrect RedirectURL: want=%#v got=%#v", ci.Metadata.RedirectURLs[0], ses.RedirectURL)
	}

	if ci.Credentials.ID != ses.ClientID {
		t.Fatalf("Session created with incorrect ClientID: want=%q got=%q", ci.Credentials.ID, ses.ClientID)
	}

	if state != ses.ClientState {
		t.Fatalf("Session created with incorrect State: want=%q got=%q", state, ses.ClientState)
	}

	if nonce != ses.Nonce {
		t.Fatalf("Session created with incorrect Nonce: want=%q got=%q", nonce, ses.Nonce)
	}
}

func TestServerLogin(t *testing.T) {
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
		Metadata: oidc.ClientMetadata{
			RedirectURLs: []url.URL{
				url.URL{
					Scheme: "http",
					Host:   "client.example.com",
					Path:   "/callback",
				},
			},
		},
	}
	ciRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{ci})

	km := &StaticKeyManager{
		signer: &StaticSigner{sig: []byte("beer"), err: nil},
	}

	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	sm.GenerateCode = staticGenerateCodeFunc("fakecode")
	sessionID, err := sm.NewSession("test_connector_id", ci.Credentials.ID, "bogus", ci.Metadata.RedirectURLs[0], "", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	userRepo, err := makeNewUserRepo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	srv := &Server{
		IssuerURL:          url.URL{Scheme: "http", Host: "server.example.com"},
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
		UserRepo:           userRepo,
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
	ciRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{
		oidc.ClientIdentity{
			Credentials: oidc.ClientCredentials{
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
		Credentials: oidc.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
	}
	ciRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{ci})
	km := &StaticKeyManager{
		signer: &StaticSigner{sig: []byte("beer"), err: nil},
	}
	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())

	userRepo, err := makeNewUserRepo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	refreshTokenRepo, err := refreshtest.NewTestRefreshTokenRepo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	srv := &Server{
		IssuerURL:          url.URL{Scheme: "http", Host: "server.example.com"},
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
		UserRepo:           userRepo,
		RefreshTokenRepo:   refreshTokenRepo,
	}

	sessionID, err := sm.NewSession("bogus_idpc", ci.Credentials.ID, "bogus", url.URL{}, "", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, err = sm.AttachRemoteIdentity(sessionID, oidc.Identity{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = sm.AttachUser(sessionID, "testid-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	key, err := sm.NewSessionKey(sessionID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jwt, token, err := srv.CodeToken(ci.Credentials, key)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if jwt == nil {
		t.Fatalf("Expected non-nil jwt")
	}
	if token == "" {
		t.Fatalf("Expected non-empty refresh token")
	}
}

func TestServerTokenUnrecognizedKey(t *testing.T) {
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID:     "XXX",
			Secret: "secrete",
		},
	}
	ciRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{ci})
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

	sessionID, err := sm.NewSession("connector_id", ci.Credentials.ID, "bogus", url.URL{}, "", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = sm.AttachRemoteIdentity(sessionID, oidc.Identity{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jwt, token, err := srv.CodeToken(ci.Credentials, "foo")
	if err == nil {
		t.Fatalf("Expected non-nil error")
	}
	if jwt != nil {
		t.Fatalf("Expected nil jwt")
	}
	if token != "" {
		t.Fatalf("Expected empty refresh token")
	}
}

func TestServerTokenFail(t *testing.T) {
	issuerURL := url.URL{Scheme: "http", Host: "server.example.com"}
	keyFixture := "goodkey"
	ccFixture := oidc.ClientCredentials{
		ID:     "XXX",
		Secret: "secrete",
	}
	signerFixture := &StaticSigner{sig: []byte("beer"), err: nil}

	tests := []struct {
		signer jose.Signer
		argCC  oidc.ClientCredentials
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
			argCC:  oidc.ClientCredentials{ID: "YYY"},
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

		sessionID, err := sm.NewSession("connector_id", ccFixture.ID, "bogus", url.URL{}, "", false)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		_, err = sm.AttachRemoteIdentity(sessionID, oidc.Identity{})
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}
		km := &StaticKeyManager{
			signer: tt.signer,
		}
		ciRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{
			oidc.ClientIdentity{Credentials: ccFixture},
		})

		_, err = sm.AttachUser(sessionID, "testid-1")
		if err != nil {
			t.Fatalf("case %d: Unexpected error: %v", i, err)
		}

		userRepo, err := makeNewUserRepo()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		refreshTokenRepo, err := refreshtest.NewTestRefreshTokenRepo()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		srv := &Server{
			IssuerURL:          issuerURL,
			KeyManager:         km,
			SessionManager:     sm,
			ClientIdentityRepo: ciRepo,
			UserRepo:           userRepo,
			RefreshTokenRepo:   refreshTokenRepo,
		}

		_, err = sm.NewSessionKey(sessionID)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		jwt, token, err := srv.CodeToken(tt.argCC, tt.argKey)
		if tt.err == "" {
			if err != nil {
				t.Errorf("case %d: got non-nil error: %v", i, err)
			} else if jwt == nil {
				t.Errorf("case %d: got nil JWT", i)
			} else if token == "" {
				t.Errorf("case %d: got empty refresh token", i)
			}

		} else {
			if err.Error() != tt.err {
				t.Errorf("case %d: want err %q, got %q", i, tt.err, err.Error())
			} else if jwt != nil {
				t.Errorf("case %d: got non-nil JWT", i)
			} else if token != "" {
				t.Errorf("case %d: got non-empty refresh token", i)
			}
		}
	}
}

func TestServerRefreshToken(t *testing.T) {
	issuerURL := url.URL{Scheme: "http", Host: "server.example.com"}

	credXXX := oidc.ClientCredentials{
		ID:     "XXX",
		Secret: "secret",
	}
	credYYY := oidc.ClientCredentials{
		ID:     "YYY",
		Secret: "secret",
	}

	signerFixture := &StaticSigner{sig: []byte("beer"), err: nil}

	tests := []struct {
		token    string
		clientID string // The client that associates with the token.
		creds    oidc.ClientCredentials
		signer   jose.Signer
		err      string
	}{
		// Everything is good.
		{
			"0/refresh-1",
			"XXX",
			credXXX,
			signerFixture,
			"",
		},
		// Invalid refresh token(malformatted).
		{
			"invalid-token",
			"XXX",
			credXXX,
			signerFixture,
			oauth2.ErrorInvalidRequest,
		},
		// Invalid refresh token.
		{
			"0/refresh-1",
			"XXX",
			credXXX,
			signerFixture,
			oauth2.ErrorInvalidRequest,
		},
		// Invalid client(client is not associated with the token).
		{
			"0/refresh-1",
			"XXX",
			credYYY,
			signerFixture,
			oauth2.ErrorInvalidClient,
		},
		// Invalid client(no client ID).
		{
			"0/refresh-1",
			"XXX",
			oidc.ClientCredentials{ID: "", Secret: "aaa"},
			signerFixture,
			oauth2.ErrorInvalidClient,
		},
		// Invalid client(no such client).
		{
			"0/refresh-1",
			"XXX",
			oidc.ClientCredentials{ID: "AAA", Secret: "aaa"},
			signerFixture,
			oauth2.ErrorInvalidClient,
		},
		// Invalid client(no secrets).
		{
			"0/refresh-1",
			"XXX",
			oidc.ClientCredentials{ID: "XXX"},
			signerFixture,
			oauth2.ErrorInvalidClient,
		},
		// Invalid client(invalid secret).
		{
			"0/refresh-1",
			"XXX",
			oidc.ClientCredentials{ID: "XXX", Secret: "bad-secret"},
			signerFixture,
			oauth2.ErrorInvalidClient,
		},
		// Signing operation fails.
		{
			"0/refresh-1",
			"XXX",
			credXXX,
			&StaticSigner{sig: nil, err: errors.New("fail")},
			oauth2.ErrorServerError,
		},
	}

	for i, tt := range tests {
		km := &StaticKeyManager{
			signer: tt.signer,
		}

		ciRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{
			oidc.ClientIdentity{Credentials: credXXX},
			oidc.ClientIdentity{Credentials: credYYY},
		})

		userRepo, err := makeNewUserRepo()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		refreshTokenRepo, err := refreshtest.NewTestRefreshTokenRepo()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		srv := &Server{
			IssuerURL:          issuerURL,
			KeyManager:         km,
			ClientIdentityRepo: ciRepo,
			UserRepo:           userRepo,
			RefreshTokenRepo:   refreshTokenRepo,
		}

		if _, err := refreshTokenRepo.Create("testid-1", tt.clientID); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		jwt, err := srv.RefreshToken(tt.creds, tt.token)
		if err != nil {
			if err.Error() != tt.err {
				t.Errorf("Case %d: expect: %v, got: %v", i, tt.err, err)
			}
		}

		if jwt != nil {
			if string(jwt.Signature) != "beer" {
				t.Errorf("Case %d: expect signature: beer, got signature: %v", i, jwt.Signature)
			}
			claims, err := jwt.Claims()
			if err != nil {
				t.Errorf("Case %d: unexpected error: %v", i, err)
			}
			if claims["iss"] != issuerURL.String() || claims["sub"] != "testid-1" || claims["aud"] != "XXX" {
				t.Errorf("Case %d: invalid claims: %v", i, claims)
			}
		}
	}

	// Test that we should return error when user cannot be found after
	// verifying the token.
	km := &StaticKeyManager{
		signer: signerFixture,
	}

	ciRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{
		oidc.ClientIdentity{Credentials: credXXX},
		oidc.ClientIdentity{Credentials: credYYY},
	})

	userRepo, err := makeNewUserRepo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Create a user that will be removed later.
	if err := userRepo.Create(nil, user.User{
		ID:    "testid-2",
		Email: "test-2@example.com",
	}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	refreshTokenRepo, err := refreshtest.NewTestRefreshTokenRepo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	srv := &Server{
		IssuerURL:          issuerURL,
		KeyManager:         km,
		ClientIdentityRepo: ciRepo,
		UserRepo:           userRepo,
		RefreshTokenRepo:   refreshTokenRepo,
	}

	if _, err := refreshTokenRepo.Create("testid-2", credXXX.ID); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Recreate the user repo to remove the user we created.
	userRepo, err = makeNewUserRepo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	srv.UserRepo = userRepo

	_, err = srv.RefreshToken(credXXX, "0/refresh-1")
	if err == nil || err.Error() != oauth2.ErrorServerError {
		t.Errorf("Expect: %v, got: %v", oauth2.ErrorServerError, err)
	}
}
