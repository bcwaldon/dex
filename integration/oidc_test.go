package integration

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/server"
	"github.com/coreos-inc/auth/session"
)

func TestHTTPExchangeToken(t *testing.T) {
	user := connector.LocalUser{
		ID:       "elroy77",
		Name:     "Elroy",
		Email:    "elroy@example.com",
		Password: "bones",
	}

	cfg := &connector.LocalConnectorConfig{
		Users: []connector.LocalUser{user},
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

	srv := &server.Server{
		IssuerURL:          issuerURL,
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: cir,
		Templates:          template.New(connector.LoginPageTemplateName),
		Connectors:         []connector.Connector{},
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
	m.HandleFunc("/callback", handleCallbackFunc(cl))
	cClient := &phttp.HandlerClient{Handler: m}

	// this will actually happen due to some interaction between the
	// end-user and a remote identity provider
	sessionID, err := sm.NewSession(ci.Credentials.ID, "bogus", url.URL{})
	if err != nil {
		t.Fatalf("Unexpected err: %v", err)
	}
	if _, err = sm.Identify(sessionID, user.Identity()); err != nil {
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
	cir := server.NewClientIdentityRepo([]oidc.ClientIdentity{ci})
	issuerURL := url.URL{Scheme: "http", Host: "server.example.com"}

	k, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Unable to generate private key: %v", err)
	}

	km := key.NewPrivateKeyManager()
	err = km.Set(key.NewPrivateKeySet([]*key.PrivateKey{k}, time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	srv := &server.Server{
		IssuerURL:          issuerURL,
		KeyManager:         km,
		ClientIdentityRepo: cir,
		SessionManager:     sm,
	}

	ns := issuerURL
	ns.Path = path.Join(ns.Path, "/auth")

	hdlr := srv.HTTPHandler()
	sClient := &phttp.HandlerClient{Handler: hdlr}

	cfg, err := oidc.FetchProviderConfig(sClient, issuerURL.String())
	if err != nil {
		t.Fatalf("Failed to fetch provider config: %v", err)
	}

	ks := key.NewPublicKeySet([]jose.JWK{k.JWK()}, time.Now().Add(1*time.Hour))
	ccfg := oidc.ClientConfig{
		HTTPClient:     sClient,
		ProviderConfig: cfg,
		Credentials:    ci.Credentials,
		KeySet:         *ks,
	}

	cl, err := oidc.NewClient(ccfg)
	if err != nil {
		t.Fatalf("Failed creating client: %v", err)
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

	if iss := claims["iss"].(string); iss != issuerURL.String() {
		t.Fatalf("unexpected claim value for iss, got=%v, want=%v", iss, issuerURL.String())
	}
}

func handleCallbackFunc(c *oidc.Client) http.HandlerFunc {
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

		if _, err := tok.Claims(); err != nil {
			phttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unable to construct claims: %v", err))
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
