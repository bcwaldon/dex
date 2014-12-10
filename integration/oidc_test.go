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
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/health"
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

	cfg := connector.ConnectorConfigLocal{
		Users: []connector.LocalUser{user},
	}

	ci := oauth2.ClientIdentity{
		ID:     "72de74a9",
		Secret: "XXX",
	}

	cir := server.NewClientIdentityRepo([]oauth2.ClientIdentity{ci})

	issuerURL := "http://server.example.com"
	sm := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())

	k, err := key.GeneratePrivateRSAKey()
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}

	km := key.NewPrivateKeyManager()
	err = km.Set(key.NewPrivateKeySet([]key.PrivateKey{k}, time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	srv := &server.Server{
		IssuerURL:          issuerURL,
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: cir,
	}

	ns, _ := url.Parse(issuerURL)
	ns.Path = path.Join(ns.Path, server.HttpPathAuth)
	idpc, err := cfg.Connector(*ns, srv.Login, template.New(connector.LoginPageTemplateName))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	idpcs := map[string]connector.Connector{
		"fake": idpc,
	}

	hdlr := srv.HTTPHandler(idpcs, []health.Checkable{})
	sClient := &phttp.HandlerClient{Handler: hdlr}

	pcfg, err := oidc.FetchProviderConfig(sClient, issuerURL)
	if err != nil {
		t.Fatalf("Failed to fetch provider config: %v", err)
	}

	cl := &oidc.Client{
		HTTPClient:     sClient,
		ProviderConfig: pcfg,
		ClientIdentity: ci,
		RedirectURL:    "http://client.example.com",
		Keys: []key.PublicKey{
			key.NewPublicKey(k.JWK()),
		},
	}

	m := http.NewServeMux()
	m.HandleFunc("/callback", handleCallbackFunc(cl))
	cClient := &phttp.HandlerClient{Handler: m}

	// this will actually happen due to some interaction between the
	// end-user and a remote identity provider
	sessionID, err := sm.NewSession(ci.ID, "bogus", url.URL{})
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
	ci := oauth2.ClientIdentity{
		ID:     "72de74a9",
		Secret: "XXX",
	}
	cir := server.NewClientIdentityRepo([]oauth2.ClientIdentity{ci})
	issuerURL := "http://server.example.com"

	k, err := key.GeneratePrivateRSAKey()
	if err != nil {
		t.Fatalf("Unable to generate RSA key: %v", err)
	}

	km := key.NewPrivateKeyManager()
	err = km.Set(key.NewPrivateKeySet([]key.PrivateKey{k}, time.Now().Add(time.Minute)))
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

	ns, _ := url.Parse(issuerURL)
	ns.Path = path.Join(ns.Path, server.HttpPathAuth)

	idpcs := map[string]connector.Connector{}
	hdlr := srv.HTTPHandler(idpcs, []health.Checkable{})
	sClient := &phttp.HandlerClient{Handler: hdlr}

	cfg, err := oidc.FetchProviderConfig(sClient, issuerURL)
	if err != nil {
		t.Fatalf("Failed to fetch provider config: %v", err)
	}

	cl := &oidc.Client{
		HTTPClient:     sClient,
		ProviderConfig: cfg,
		ClientIdentity: ci,
		Keys: []key.PublicKey{
			key.NewPublicKey(k.JWK()),
		},
	}

	tok, err := cl.ClientCredsToken([]string{"openid"})
	if err != nil {
		t.Fatalf("Failed getting client token: %v", err)
	}

	claims, err := tok.Claims()
	if err != nil {
		t.Fatalf("Failed parsing claims from client token: %v", err)
	}

	if aud := claims["aud"].(string); aud != ci.ID {
		t.Fatalf("unexpected claim value for aud, got=%v, want=%v", aud, ci.ID)
	}

	if sub := claims["sub"].(string); sub != ci.ID {
		t.Fatalf("unexpected claim value for sub, got=%v, want=%v", sub, ci.ID)
	}

	if name := claims["name"].(string); name != ci.ID {
		t.Fatalf("unexpected claim value for name, got=%v, want=%v", name, ci.ID)
	}

	if iss := claims["iss"].(string); iss != issuerURL {
		t.Fatalf("unexpected claim value for iss, got=%v, want=%v", iss, issuerURL)
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
