package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"testing"

	localconnector "github.com/coreos-inc/auth/connector/local"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/server"
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

	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Unable to generate RSA private key: %v", err)
	}
	signer := josesig.NewSignerRSA("123", *pk)

	idp := localconnector.NewLocalIdentityProvider([]localconnector.User{user})

	cir := server.NewClientIdentityRepo([]oauth2.ClientIdentity{ci})

	issuerURL := "http://server.example.com"
	sm := server.NewSessionManager(issuerURL, signer)

	srv := &server.Server{
		IssuerURL:          issuerURL,
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: cir,
	}

	ns, _ := url.Parse(issuerURL)
	ns.Path = path.Join(ns.Path, server.HttpPathAuthIDPC)
	idpc := localconnector.NewLocalIDPConnector(*ns, srv.Login, idp)

	sClient := &phttp.HandlerClient{Handler: srv.HTTPHandler(idpc)}

	cfg, err := oidc.FetchProviderConfig(sClient, issuerURL)
	if err != nil {
		t.Fatalf("Failed to fetch provider config: %v", err)
	}

	cl := &oidc.Client{
		HTTPClient:     sClient,
		ProviderConfig: *cfg,
		ClientIdentity: ci,
		RedirectURL:    "http://client.example.com",
	}

	if err = cl.RefreshKeys(); err != nil {
		t.Fatalf("Failed refreshing keys: %v", err)
	}

	m := http.NewServeMux()
	m.HandleFunc("/callback", handleCallbackFunc(cl))
	cClient := &phttp.HandlerClient{Handler: m}

	// this will actually happen due to some interaction between the
	// end-user and a remote identity provider
	ses := sm.NewSession(ci)
	if err := ses.Identify(user.Identity()); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://client.example.com/callback?code=%s", ses.NewKey()), nil)
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
