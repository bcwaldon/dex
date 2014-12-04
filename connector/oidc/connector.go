package oidc

import (
	"fmt"
	"html/template"
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

type OIDCIDPConnectorConfig struct {
	id string

	IssuerURL    string
	ClientID     string
	ClientSecret string
}

func (cfg *OIDCIDPConnectorConfig) ConnectorID() string {
	return cfg.id
}

type OIDCIDPConnector struct {
	client    *oidc.Client
	namespace url.URL
	loginFunc oidc.LoginFunc
}

func (cfg *OIDCIDPConnectorConfig) Connector(ns url.URL, lf oidc.LoginFunc, tpls *template.Template) (connector.IDPConnector, error) {
	ci := oauth2.ClientIdentity{
		ID:     cfg.ClientID,
		Secret: cfg.ClientSecret,
	}

	pcfg, err := oidc.FetchProviderConfig(http.DefaultClient, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch provider config: %v", err)
	}

	cbURL := ns
	cbURL.Path = path.Join(cbURL.Path, "/callback")
	c := &oidc.Client{
		ProviderConfig: pcfg,
		ClientIdentity: ci,
		RedirectURL:    cbURL.String(),
	}

	c.SyncKeys()

	idpc := &OIDCIDPConnector{
		client:    c,
		namespace: ns,
		loginFunc: lf,
	}

	return idpc, nil
}

func (c *OIDCIDPConnector) DisplayType() string {
	return "OIDC"
}

func (c *OIDCIDPConnector) Healthy() error {
	return c.client.Healthy()
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
	redirectURL := phttp.MergeQuery(errorURL, q)
	w.Header().Set("Location", redirectURL.String())
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
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "code query param must be set")
			redirectError(w, errorURL, q)
			return
		}

		tok, err := c.ExchangeAuthCode(code)
		if err != nil {
			log.Printf("unable to verify auth code with issuer: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to verify auth code with issuer")
			redirectError(w, errorURL, q)
			return
		}

		claims, err := tok.Claims()
		if err != nil {
			log.Printf("unable to construct claims: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to construct claims")
			redirectError(w, errorURL, q)
			return
		}

		ident, err := oidc.IdentityFromClaims(claims)
		if err != nil {
			log.Printf("Failed parsing claims from remote provider: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to convert claims to identity")
			redirectError(w, errorURL, q)
			return
		}

		sessionKey := q.Get("state")
		if sessionKey == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "missing state query param")
			redirectError(w, errorURL, q)
			return
		}

		redirectURL, err := lf(*ident, sessionKey)
		if err != nil {
			log.Printf("Unable to log in %#v: %v", *ident, err)
			q.Set("error", oauth2.ErrorAccessDenied)
			q.Set("error_description", "login failed")
			redirectError(w, errorURL, q)
			return
		}

		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
}
