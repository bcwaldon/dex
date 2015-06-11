package integration

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/server"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
)

func mockServer(cis []oidc.ClientIdentity) (*server.Server, error) {
	k, err := key.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("Unable to generate private key: %v", err)
	}

	km := key.NewPrivateKeyManager()
	err = km.Set(key.NewPrivateKeySet([]*key.PrivateKey{k}, time.Now().Add(time.Minute)))
	if err != nil {
		return nil, err
	}

	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	srv := &server.Server{
		IssuerURL:          url.URL{Scheme: "http", Host: "server.example.com"},
		KeyManager:         km,
		ClientIdentityRepo: server.NewClientIdentityRepo(cis),
		SessionManager:     sm,
	}

	return srv, nil
}

func mockClient(srv *server.Server, ci oidc.ClientIdentity) (*oidc.Client, error) {
	hdlr := srv.HTTPHandler()
	sClient := &phttp.HandlerClient{Handler: hdlr}

	cfg, err := oidc.FetchProviderConfig(sClient, srv.IssuerURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider config: %v", err)
	}

	jwks, err := srv.KeyManager.JWKs()
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWKs: %v", err)
	}

	ks := key.NewPublicKeySet(jwks, time.Now().Add(1*time.Hour))
	ccfg := oidc.ClientConfig{
		HTTPClient:     sClient,
		ProviderConfig: cfg,
		Credentials:    ci.Credentials,
		KeySet:         *ks,
	}

	return oidc.NewClient(ccfg)
}

func TestHTTPExchangeToken(t *testing.T) {
	password, err := user.NewPasswordFromPlaintext("woof")
	if err != nil {
		t.Fatalf("unexpectd error: %q", err)
	}

	passwordInfo := user.PasswordInfo{
		UserID:   "elroy77",
		Password: password,
	}

	cfg := &connector.LocalConnectorConfig{
		PasswordInfos: []user.PasswordInfo{passwordInfo},
	}

	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID:     "72de74a9",
			Secret: "XXX",
		},
	}

	cir := server.NewClientIdentityRepo([]oidc.ClientIdentity{ci})

	issuerURL := url.URL{Scheme: "http", Host: "server.example.com"}
	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())

	k, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}

	km := key.NewPrivateKeyManager()
	err = km.Set(key.NewPrivateKeySet([]*key.PrivateKey{k}, time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	usr := user.User{
		Name:        "testname",
		DisplayName: "displayname",
	}
	userRepo := user.NewUserRepo()
	if userID, err := userRepo.Create(usr); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	} else {
		usr.ID = userID
	}

	passwordInfoRepo := user.NewPasswordInfoRepo()

	srv := &server.Server{
		IssuerURL:          issuerURL,
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: cir,
		Templates:          template.New(connector.LoginPageTemplateName),
		Connectors:         []connector.Connector{},
		UserRepo:           userRepo,
		PasswordInfoRepo:   passwordInfoRepo,
	}

	if err = srv.AddConnector(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sClient := &phttp.HandlerClient{Handler: srv.HTTPHandler()}
	pcfg, err := oidc.FetchProviderConfig(sClient, issuerURL.String())
	if err != nil {
		t.Fatalf("Failed to fetch provider config: %v", err)
	}

	ks := key.NewPublicKeySet([]jose.JWK{k.JWK()}, time.Now().Add(1*time.Hour))

	ccfg := oidc.ClientConfig{
		HTTPClient:     sClient,
		ProviderConfig: pcfg,
		Credentials:    ci.Credentials,
		RedirectURL:    "http://client.example.com",
		KeySet:         *ks,
	}

	cl, err := oidc.NewClient(ccfg)
	if err != nil {
		t.Fatalf("Failed creating oidc.Client: %v", err)
	}

	m := http.NewServeMux()

	var claims jose.Claims
	m.HandleFunc("/callback", handleCallbackFunc(cl, &claims))
	cClient := &phttp.HandlerClient{Handler: m}

	// this will actually happen due to some interaction between the
	// end-user and a remote identity provider
	sessionID, err := sm.NewSession("bogus_idpc", ci.Credentials.ID, "bogus", url.URL{}, false)
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	if _, err = sm.AttachRemoteIdentity(sessionID, passwordInfo.Identity()); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err = sm.AttachUser(sessionID, usr.ID); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	key, err := sm.NewSessionKey(sessionID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://client.example.com/callback?code=%s", key), nil)
	if err != nil {
		t.Fatalf("Failed creating HTTP request: %v", err)
	}

	resp, err := cClient.Do(req)
	if err != nil {
		t.Fatalf("Failed resolving HTTP requests against /callback: %v", err)
	}

	if claims["name"] != usr.DisplayName {
		t.Errorf("want=%#v, got=%#v", usr.DisplayName, claims["name"])
	}
	if claims["preferred_username"] != usr.Name {
		t.Errorf("want=%#v, got=%#v", usr.Name, claims["preferred_name"])
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Received status code %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestHTTPClientCredsToken(t *testing.T) {
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID:     "72de74a9",
			Secret: "XXX",
		},
	}
	cis := []oidc.ClientIdentity{ci}

	srv, err := mockServer(cis)
	if err != nil {
		t.Fatalf("Unexpected error setting up server: %v", err)
	}

	cl, err := mockClient(srv, ci)
	if err != nil {
		t.Fatalf("Unexpected error setting up OIDC client: %v", err)
	}

	tok, err := cl.ClientCredsToken([]string{"openid"})
	if err != nil {
		t.Fatalf("Failed getting client token: %v", err)
	}

	claims, err := tok.Claims()
	if err != nil {
		t.Fatalf("Failed parsing claims from client token: %v", err)
	}

	if aud := claims["aud"].(string); aud != ci.Credentials.ID {
		t.Fatalf("unexpected claim value for aud, got=%v, want=%v", aud, ci.Credentials.ID)
	}

	if sub := claims["sub"].(string); sub != ci.Credentials.ID {
		t.Fatalf("unexpected claim value for sub, got=%v, want=%v", sub, ci.Credentials.ID)
	}

	if name := claims["name"].(string); name != ci.Credentials.ID {
		t.Fatalf("unexpected claim value for name, got=%v, want=%v", name, ci.Credentials.ID)
	}

	wantIss := srv.IssuerURL.String()
	if iss := claims["iss"].(string); iss != wantIss {
		t.Fatalf("unexpected claim value for iss, got=%v, want=%v", iss, wantIss)
	}
}

func handleCallbackFunc(c *oidc.Client, claims *jose.Claims) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			phttp.WriteError(w, http.StatusBadRequest, "code query param must be set")
			return
		}

		tok, err := c.ExchangeAuthCode(code)
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unable to verify auth code with issuer: %v", err))
			return
		}

		if *claims, err = tok.Claims(); err != nil {
			phttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unable to construct claims: %v", err))
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
