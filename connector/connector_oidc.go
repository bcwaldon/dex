package connector

import (
	"html/template"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/pkg/log"
	ptime "github.com/coreos-inc/auth/pkg/time"
)

const (
	OIDCConnectorType = "oidc"
	httpPathCallback  = "/callback"
)

func init() {
	RegisterConnectorConfigType(OIDCConnectorType, func() ConnectorConfig { return &OIDCConnectorConfig{} })
}

type OIDCConnectorConfig struct {
	ID           string `json:"id"`
	IssuerURL    string `json:"issuerURL"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}

func (cfg *OIDCConnectorConfig) ConnectorID() string {
	return cfg.ID
}

func (cfg *OIDCConnectorConfig) ConnectorType() string {
	return OIDCConnectorType
}

type OIDCConnector struct {
	issuerURL string
	cbURL     url.URL
	loginFunc oidc.LoginFunc
	client    *oidc.Client
}

func (cfg *OIDCConnectorConfig) Connector(ns url.URL, lf oidc.LoginFunc, tpls *template.Template) (Connector, error) {
	ns.Path = path.Join(ns.Path, httpPathCallback)
	idpc := &OIDCConnector{
		issuerURL: cfg.IssuerURL,
		cbURL:     ns,
		loginFunc: lf,
		client: &oidc.Client{
			RedirectURL: ns.String(),
			ClientIdentity: oauth2.ClientIdentity{
				ID:     cfg.ClientID,
				Secret: cfg.ClientSecret,
			},
		},
	}
	return idpc, nil
}

func (c *OIDCConnector) Healthy() error {
	return c.client.Healthy()
}

func (c *OIDCConnector) LoginURL(sessionKey, prompt string) (string, error) {
	oac, err := c.client.OAuthClient()
	if err != nil {
		return "", err
	}

	return oac.AuthCodeURL(sessionKey, "", prompt), nil
}

func (c *OIDCConnector) Register(mux *http.ServeMux, errorURL url.URL) {
	mux.Handle(c.cbURL.Path, c.handleCallbackFunc(c.loginFunc, errorURL))
}

func (c *OIDCConnector) Sync() chan struct{} {
	stop := make(chan struct{})
	go func() {
		c.client.ProviderConfig = func() oidc.ProviderConfig {
			var sleep time.Duration
			for {
				pcfg, err := oidc.FetchProviderConfig(http.DefaultClient, c.issuerURL)
				if err == nil {
					return pcfg
				}

				sleep = ptime.ExpBackoff(sleep, time.Minute)
				log.Errorf("Failed fetching provider config, trying again in %v: %v", sleep, err)
				time.Sleep(sleep)
			}
		}()

		log.Infof("Fetched provider config from %s: %#v", c.issuerURL, c.client.ProviderConfig)

		c.client.SyncProviderConfig(c.issuerURL)
	}()
	return stop
}

func redirectError(w http.ResponseWriter, errorURL url.URL, q url.Values) {
	redirectURL := phttp.MergeQuery(errorURL, q)
	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (c *OIDCConnector) handleCallbackFunc(lf oidc.LoginFunc, errorURL url.URL) http.HandlerFunc {
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

		tok, err := c.client.ExchangeAuthCode(code)
		if err != nil {
			log.Errorf("Unable to verify auth code with issuer: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to verify auth code with issuer")
			redirectError(w, errorURL, q)
			return
		}

		claims, err := tok.Claims()
		if err != nil {
			log.Errorf("Unable to construct claims: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to construct claims")
			redirectError(w, errorURL, q)
			return
		}

		ident, err := oidc.IdentityFromClaims(claims)
		if err != nil {
			log.Errorf("Failed parsing claims from remote provider: %v", err)
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
			log.Errorf("Unable to log in %#v: %v", *ident, err)
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
