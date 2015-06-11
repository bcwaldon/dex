package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos/pkg/health"
)

const (
	lastSeenMaxAge  = time.Minute * 5
	discoveryMaxAge = time.Hour * 24
)

var (
	httpPathDiscovery = "/.well-known/openid-configuration"
	httpPathToken     = "/token"
	httpPathKeys      = "/keys"
	httpPathAuth      = "/auth"
	httpPathHealth    = "/health"
	httpPathAPI       = "/api"
	httpPathRegister  = "/register"
)

func handleDiscoveryFunc(cfg oidc.ProviderConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET only acceptable method")
			return
		}

		b, err := json.Marshal(cfg)
		if err != nil {
			log.Errorf("Unable to marshal %#v to JSON: %v", cfg, err)
		}

		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(discoveryMaxAge.Seconds())))
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
}

func handleKeysFunc(km key.PrivateKeyManager, clock clockwork.Clock) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET only acceptable method")
			return
		}

		jwks, err := km.JWKs()
		if err != nil {
			log.Errorf("Failed to get JWKs while serving HTTP request: %v", err)
			phttp.WriteError(w, http.StatusInternalServerError, "")
			return
		}

		keys := struct {
			Keys []jose.JWK `json:"keys"`
		}{
			Keys: jwks,
		}

		b, err := json.Marshal(keys)
		if err != nil {
			log.Errorf("Unable to marshal signing key to JSON: %v", err)
		}

		exp := km.ExpiresAt()
		w.Header().Set("Expires", exp.Format(time.RFC1123))

		ttl := int(exp.Sub(clock.Now().UTC()).Seconds())
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", ttl))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

type templateData struct {
	Error       bool
	Message     string
	Instruction string
	Detail      string
	Links       []struct {
		URL string
		ID  string
	}
}

func execTemplate(w http.ResponseWriter, tpl *template.Template, data interface{}) {
	execTemplateWithStatus(w, tpl, data, http.StatusOK)
}

func execTemplateWithStatus(w http.ResponseWriter, tpl *template.Template, data interface{}, status int) {
	w.WriteHeader(status)
	if err := tpl.Execute(w, data); err != nil {
		phttp.WriteError(w, http.StatusInternalServerError, "error loading page")
		return
	}
}

func renderLoginPage(w http.ResponseWriter, r *http.Request, srv OIDCServer, idpcs []connector.Connector, tpl *template.Template) {
	if tpl == nil {
		phttp.WriteError(w, http.StatusInternalServerError, "error loading login page")
		return
	}

	td := templateData{
		Message:     "Error",
		Instruction: "Please try again or contact the system administrator",
	}

	// Render error if remote IdP connector errored and redirected here.
	q := r.URL.Query()
	e := q.Get("error")
	connectorID := q.Get("connector_id")
	if e != "" {
		td.Error = true
		td.Message = "Authentication Error"
		remoteMsg := q.Get("error_description")
		if remoteMsg == "" {
			remoteMsg = q.Get("error")
		}
		if connectorID == "" {
			td.Detail = remoteMsg
		} else {
			td.Detail = fmt.Sprintf("Error from %s: %s.", connectorID, remoteMsg)
		}
		execTemplate(w, tpl, td)
		return
	}

	// Render error message if client id is invalid.
	clientID := q.Get("client_id")
	cm, err := srv.ClientMetadata(clientID)
	if err != nil {
		log.Errorf("Failed fetching client %q from repo: %v", clientID, err)
		td.Error = true
		td.Message = "Server Error"
		execTemplate(w, tpl, td)
		return
	} else if cm == nil {
		td.Error = true
		td.Message = "Authentication Error"
		td.Detail = "Invalid client ID"
		execTemplate(w, tpl, td)
		return
	}

	if len(idpcs) == 0 {
		td.Error = true
		td.Message = "Server Error"
		td.Instruction = "Unable to authenticate users at this time"
		td.Detail = "Authentication service may be misconfigured"
		execTemplate(w, tpl, td)
		return
	}

	td.Links = make([]struct {
		URL string
		ID  string
	}, len(idpcs))

	n := 0
	for _, idpc := range idpcs {
		td.Links[n].ID = idpc.ID()

		v := r.URL.Query()
		v.Set("connector_id", idpc.ID())
		v.Set("response_type", "code")
		td.Links[n].URL = httpPathAuth + "?" + v.Encode()
		n++
	}

	execTemplate(w, tpl, td)
}

func handleAuthFunc(srv OIDCServer, idpcs []connector.Connector, tpl *template.Template) http.HandlerFunc {
	idx := makeConnectorMap(idpcs)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET only acceptable method")
			return
		}

		q := r.URL.Query()
		e := q.Get("error")
		if e != "" {
			sessionKey := q.Get("state")
			if err := srv.KillSession(sessionKey); err != nil {
				log.Errorf("Failed killing sessionKey %q: %v", sessionKey, err)
			}
			renderLoginPage(w, r, srv, idpcs, tpl)
			return
		}

		connectorID := q.Get("connector_id")
		idpc, ok := idx[connectorID]
		if !ok {
			renderLoginPage(w, r, srv, idpcs, tpl)
			return
		}

		acr, err := oauth2.ParseAuthCodeRequest(q)
		if err != nil {
			log.Debugf("Invalid auth request")
			writeAuthError(w, err, acr.State)
			return
		}

		cm, err := srv.ClientMetadata(acr.ClientID)
		if err != nil {
			log.Errorf("Failed fetching client %q from repo: %v", acr.ClientID, err)
			writeAuthError(w, oauth2.NewError(oauth2.ErrorServerError), acr.State)
			return
		}
		if cm == nil {
			log.Debugf("Client %q not found", acr.ClientID)
			writeAuthError(w, oauth2.NewError(oauth2.ErrorInvalidRequest), acr.State)
			return
		}

		if len(cm.RedirectURLs) == 0 {
			log.Errorf("Client %q has no redirect URLs", acr.ClientID)
			writeAuthError(w, oauth2.NewError(oauth2.ErrorServerError), acr.State)
			return
		}

		var redirectURL *url.URL

		if acr.RedirectURL == nil {
			if len(cm.RedirectURLs) > 1 {
				log.Debugf("Request must provide redirect URL as client %q has registered many", acr.ClientID)
				writeAuthError(w, oauth2.NewError(oauth2.ErrorInvalidRequest), acr.State)
				return
			} else {
				redirectURL = &cm.RedirectURLs[0]
			}
		} else {
			for _, ru := range cm.RedirectURLs {
				if reflect.DeepEqual(*acr.RedirectURL, ru) {
					redirectURL = &ru
				}
			}

			if redirectURL == nil {
				log.Debugf("Request provided unregistered redirect URL: %s", acr.RedirectURL)
				writeAuthError(w, oauth2.NewError(oauth2.ErrorInvalidRequest), acr.State)
				return
			}
		}

		if acr.ResponseType != oauth2.ResponseTypeCode {
			redirectAuthError(w, oauth2.NewError(oauth2.ErrorUnsupportedResponseType), acr.State, *redirectURL)
			return
		}

		register := q.Get("register") == "1"
		key, err := srv.NewSession(connectorID, acr.ClientID, acr.State, *redirectURL, register)
		if err != nil {
			redirectAuthError(w, err, acr.State, *redirectURL)
			return
		}

		if register {
			_, ok := idpc.(*connector.LocalConnector)
			if ok {
				q := url.Values{}
				q.Set("code", key)
				ru := httpPathRegister + "?" + q.Encode()
				w.Header().Set("Location", ru)
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
		}

		var p string
		if shouldReprompt(r) {
			p = "force"
		}
		lu, err := idpc.LoginURL(key, p)
		if err != nil {
			log.Errorf("Connector.LoginURL failed: %v", err)
			redirectAuthError(w, err, acr.State, *redirectURL)
			return
		}

		http.SetCookie(w, createLastSeenCookie())
		w.Header().Set("Location", lu)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
}

func handleTokenFunc(srv OIDCServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			phttp.WriteError(w, http.StatusMethodNotAllowed, fmt.Sprintf("POST only acceptable method"))
			return
		}

		err := r.ParseForm()
		if err != nil {
			writeTokenError(w, oauth2.NewError(oauth2.ErrorInvalidRequest), "")
			return
		}

		state := r.PostForm.Get("state")

		user, password, ok := phttp.BasicAuth(r)
		if !ok {
			writeTokenError(w, oauth2.NewError(oauth2.ErrorInvalidClient), state)
			return
		}

		creds := oidc.ClientCredentials{ID: user, Secret: password}

		var jwt *jose.JWT
		grantType := r.PostForm.Get("grant_type")

		switch grantType {
		case oauth2.GrantTypeAuthCode:
			code := r.PostForm.Get("code")
			if code == "" {
				writeTokenError(w, oauth2.NewError(oauth2.ErrorInvalidRequest), state)
				return
			}

			jwt, err = srv.CodeToken(creds, code)
			if err != nil {
				writeTokenError(w, err, state)
				return
			}
		case oauth2.GrantTypeClientCreds:
			jwt, err = srv.ClientCredsToken(creds)
			if err != nil {
				writeTokenError(w, err, state)
				return
			}
		default:
			writeTokenError(w, oauth2.NewError(oauth2.ErrorUnsupportedGrantType), state)
			return
		}

		t := oAuth2Token{
			AccessToken: jwt.Encode(),
			IDToken:     jwt.Encode(),
			TokenType:   "bearer",
		}

		b, err := json.Marshal(t)
		if err != nil {
			log.Errorf("Failed marshaling %#v to JSON: %v", t, err)
			writeTokenError(w, oauth2.NewError(oauth2.ErrorServerError), state)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

func handleHealthFunc(checks []health.Checkable) http.HandlerFunc {
	return health.Checker{
		Checks: checks,
	}.MakeHealthHandlerFunc()
}

type oAuth2Token struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

func createLastSeenCookie() *http.Cookie {
	now := time.Now().UTC()
	return &http.Cookie{
		HttpOnly: true,
		Name:     "LastSeen",
		MaxAge:   int(lastSeenMaxAge.Seconds()),
		// For old IE, ignored by most browsers.
		Expires: now.Add(lastSeenMaxAge),
	}
}

// shouldReprompt determines if user should be re-prompted for login based on existance of a cookie.
func shouldReprompt(r *http.Request) bool {
	_, err := r.Cookie("LastSeen")
	if err == nil {
		return true
	}
	return false
}

func makeConnectorMap(idpcs []connector.Connector) map[string]connector.Connector {
	idx := make(map[string]connector.Connector, len(idpcs))
	for _, idpc := range idpcs {
		idx[idpc.ID()] = idpc
	}
	return idx
}
