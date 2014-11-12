package oidc

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

const (
	OIDCIDPConnectorType = "oidc"
)

type OIDCIDPConnector struct {
	client    *oidc.Client
	namespace url.URL
	loginFunc oidc.LoginFunc
}

func NewOIDCIDPConnectorFromFlags(ns url.URL, lf oidc.LoginFunc, fs *flag.FlagSet) (connector.IDPConnector, error) {
	issuerURL := fs.Lookup("connector-oidc-issuer-url").Value.String()
	ci := oauth2.ClientIdentity{
		ID:     fs.Lookup("connector-oidc-client-id").Value.String(),
		Secret: fs.Lookup("connector-oidc-client-secret").Value.String(),
	}

	cfg, err := oidc.FetchProviderConfig(http.DefaultClient, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch provider config: %v", err)
	}

	cbURL := ns
	cbURL.Path = path.Join(cbURL.Path, "/callback")
	c, err := oidc.NewClient(http.DefaultClient, *cfg, ci, cbURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create OIDC client: %v", err)
	}

	if err = c.RefreshKeys(); err != nil {
		return nil, fmt.Errorf("failed refreshing keys: %v", err)
	}

	return NewOIDCIDPConnector(ns, lf, c), nil
}

func NewOIDCIDPConnector(ns url.URL, lf oidc.LoginFunc, c *oidc.Client) *OIDCIDPConnector {
	return &OIDCIDPConnector{
		client:    c,
		namespace: ns,
		loginFunc: lf,
	}
}

func (c *OIDCIDPConnector) DisplayType() string {
	return "OIDC"
}

func (c *OIDCIDPConnector) LoginURL(r *http.Request) string {
	v := url.Values{}
	v.Set("authd_redirect_uri", r.URL.Query().Get("redirect_uri"))
	v.Set("authd_client_id", r.URL.Query().Get("client_id"))
	state := v.Encode()

	return c.client.OAuthClient.AuthCodeURL(state, "", "")
}

func (c *OIDCIDPConnector) Register(mux *http.ServeMux) {
	mux.Handle(c.namespace.Path+"/callback", handleCallbackFunc(c.loginFunc, c.client))
}

func handleCallbackFunc(lf oidc.LoginFunc, c *oidc.Client) http.HandlerFunc {
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

		claims, err := tok.Claims()
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unable to construct claims: %v", err))
			return
		}

		ident, err := oidc.IdentityFromClaims(claims)
		if err != nil {
			phttp.WriteError(w, http.StatusUnauthorized, "unable to convert claims to identity")
			return
		}

		state, err := url.ParseQuery(r.URL.Query().Get("state"))
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, "malformed state query param")
		}

		clientID := state.Get("authd_client_id")
		code, err = lf(*ident, clientID)
		if err != nil {
			log.Printf("Unable to log in identity %#v with client ID %s: %v", *ident, clientID, err)
			phttp.WriteError(w, http.StatusInternalServerError, "login failed")
			return
		}

		aru := state.Get("authd_redirect_uri")
		u, err := url.Parse(aru)
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, "invalid authd_redirect_uri")
			return
		}

		q := u.Query()
		q.Set("code", code)
		u.RawQuery = q.Encode()
		w.Header().Set("Location", u.String())

		w.WriteHeader(http.StatusTemporaryRedirect)
		return

	}
}
