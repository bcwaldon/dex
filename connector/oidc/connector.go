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
	c := &oidc.Client{
		ProviderConfig: *cfg,
		ClientIdentity: ci,
		RedirectURL:    cbURL.String(),
	}

	c.SyncKeys()

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

func (c *OIDCIDPConnector) LoginURL(sessionKey, prompt string) (string, error) {
	oac, err := c.client.OAuthClient()
	if err != nil {
		return "", err
	}

	return oac.AuthCodeURL(sessionKey, "", prompt), nil
}

func (c *OIDCIDPConnector) Register(mux *http.ServeMux, errorURL url.URL) {
	mux.Handle(c.namespace.Path+"/callback", handleCallbackFunc(c.loginFunc, c.client, errorURL))
}

func redirectError(w http.ResponseWriter, errorURL url.URL, q url.Values) {
	vals := errorURL.Query()
	for k, vs := range q {
		for _, v := range vs {
			vals.Add(k, v)
		}
	}
	errorURL.RawQuery = vals.Encode()
	w.Header().Set("Location", errorURL.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func handleCallbackFunc(lf oidc.LoginFunc, c *oidc.Client, errorURL url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		e := q.Get("error")
		if e != "" {
			redirectError(w, errorURL, q)
			return
		}

		code := q.Get("code")
		if code == "" {
			q.Set("error", "code query param must be set")
			redirectError(w, errorURL, q)
			return
		}

		tok, err := c.ExchangeAuthCode(code)
		if err != nil {
			log.Printf("unable to verify auth code with issuer: %v", err)
			q.Set("error", "unable to verify auth code with issuer")
			redirectError(w, errorURL, q)
			return
		}

		claims, err := tok.Claims()
		if err != nil {
			log.Printf("unable to construct claims: %v", err)
			q.Set("error", "unable to construct claims")
			redirectError(w, errorURL, q)
			return
		}

		ident, err := oidc.IdentityFromClaims(claims)
		if err != nil {
			q.Set("error", "unable to convert claims to identity")
			redirectError(w, errorURL, q)
			return
		}

		sessionKey := q.Get("state")
		if sessionKey == "" {
			q.Set("error", "missing state query param")
			redirectError(w, errorURL, q)
			return
		}

		redirectURL, err := lf(*ident, sessionKey)
		if err != nil {
			log.Printf("Unable to log in %#v: %v", *ident, err)
			q.Set("error", "login failed")
			redirectError(w, errorURL, q)
			return
		}

		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
}
