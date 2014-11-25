package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/coreos-inc/auth/connector"
	localconnector "github.com/coreos-inc/auth/connector/local"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/server"
	"github.com/coreos-inc/auth/session"
)

func TestHTTPExchangeToken(t *testing.T) {
	user := localconnector.User{
		ID:       "elroy77",
		Name:     "Elroy",
		Email:    "elroy@example.com",
		Password: "bones",
	}

	ci := oauth2.ClientIdentity{
		ID:     "72de74a9",
		Secret: "XXX",
	}

	idp := localconnector.NewLocalIdentityProvider([]localconnector.User{user})

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
	idpc := localconnector.NewLocalIDPConnector(*ns, srv.Login, idp)
	idpcs := make(map[string]connector.IDPConnector)
	idpcs["fake"] = idpc

	sClient := &phttp.HandlerClient{Handler: srv.HTTPHandler(idpcs, nil)}

	cfg, err := oidc.FetchProviderConfig(sClient, issuerURL)
	if err != nil {
		t.Fatalf("Failed to fetch provider config: %v", err)
	}

	cl := &oidc.Client{
		HTTPClient:     sClient,
		ProviderConfig: cfg,
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
