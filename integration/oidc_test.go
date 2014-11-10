package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"

	localconnector "github.com/coreos-inc/auth/connector/local"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	oidchttp "github.com/coreos-inc/auth/oidc/http"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/server"
)

func TestHTTPExchangeToken(t *testing.T) {
	ident := oidc.Identity{
		ID:    "d72e9ab9",
		Name:  "Elroy",
		Email: "elroy@example.com",
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

	idp := localconnector.NewLocalIdentityProvider([]oidc.Identity{ident})

	cir := server.NewClientIdentityRepo([]oauth2.ClientIdentity{ci})

	issuerURL := "http://server.example.com"
	sm := server.NewSessionManager(issuerURL, signer)

	srv := &server.Server{
		IssuerURL:          issuerURL,
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: cir,
	}

	idpc := localconnector.NewLocalIDPConnector(idp, server.HttpPathAuthIDPC, srv.Login)

	sClient := &phttp.HandlerClient{Handler: srv.HTTPHandler(idpc)}

	cfg, err := oidc.FetchProviderConfig(sClient, issuerURL)
	if err != nil {
		t.Fatalf("Failed to fetch provider config: %v", err)
	}

	cl, err := oidc.NewClient(sClient, *cfg, ci, "http://client.example.com")
	if err != nil {
		t.Fatalf("Failed creating new OIDC Client: %v", err)
	}

	if err = cl.RefreshKeys(); err != nil {
		t.Fatalf("Failed refreshing keys: %v", err)
	}

	m := http.NewServeMux()
	m.HandleFunc("/callback", oidchttp.NewClientCallbackHandlerFunc(cl))
	cClient := &phttp.HandlerClient{Handler: m}

	// this will actually happen due to some interaction between the
	// end-user and a remote identity provider
	code, err := sm.NewSession(ci, ident)
	if err != nil {
		t.Fatalf("Failed creating new session: %v", err)
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://client.example.com/callback?code=%s", code), nil)
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
