package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"reflect"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

var (
	httpPathDiscovery = "/.well-known/openid-configuration"
	httpPathToken     = "/token"
	httpPathKeys      = "/keys"
	HttpPathAuth      = "/auth"
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
			log.Printf("Unable to marshal %#v to JSON: %v", cfg, err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
}

func handleKeysFunc(keys []jose.JWK) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET only acceptable method")
			return
		}

		keys := struct {
			Keys []jose.JWK `json:"keys"`
		}{
			Keys: keys,
		}

		b, err := json.Marshal(keys)
		if err != nil {
			log.Printf("Unable to marshal signing key to JSON: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

func renderLoginPage(w http.ResponseWriter, r *http.Request, idpcs map[string]connector.IDPConnector, tpl *template.Template) {
	links := make([]struct {
		DisplayType string
		URL         string
		ID          string
	}, len(idpcs))

	n := 0
	for id, c := range idpcs {
		links[n].ID = id
		links[n].DisplayType = c.DisplayType()

		v := r.URL.Query()
		v.Set("idpc_id", id)
		links[n].URL = HttpPathAuth + "?" + v.Encode()
		n++
	}

	if tpl == nil {
		phttp.WriteError(w, http.StatusInternalServerError, "error loading login page")
		return
	}

	if err := tpl.Execute(w, links); err != nil {
		phttp.WriteError(w, http.StatusInternalServerError, "error loading login page")
		return
	}
}

func handleAuthFunc(srv OIDCServer, idpcs map[string]connector.IDPConnector, tpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET only acceptable method")
			return
		}

		q := r.URL.Query()
		idpc, ok := idpcs[q.Get("idpc_id")]
		if !ok {
			renderLoginPage(w, r, idpcs, tpl)
			return
		}

		acr, err := oauth2.ParseAuthCodeRequest(q)
		if err != nil {
			writeAuthError(w, err, acr.State)
			return
		}

		ci := srv.Client(acr.ClientID)
		if ci == nil || (acr.RedirectURL != nil && !reflect.DeepEqual(ci.RedirectURL, *acr.RedirectURL)) {
			writeAuthError(w, oauth2.NewError(oauth2.ErrorInvalidRequest), acr.State)
			return
		}

		if acr.ResponseType != oauth2.ResponseTypeCode {
			redirectAuthError(w, oauth2.NewError(oauth2.ErrorUnsupportedResponseType), acr.State, ci.RedirectURL)
			return
		}

		key, err := srv.NewSession(*ci, acr.State)
		if err != nil {
			redirectAuthError(w, err, acr.State, ci.RedirectURL)
			return
		}

		lu, err := idpc.LoginURL(key)
		if err != nil {
			log.Printf("IDPConnector.LoginURL failed: %v", err)
			redirectAuthError(w, err, acr.State, ci.RedirectURL)
			return
		}

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

		state := r.PostForm.Get("code")

		grantType := r.PostForm.Get("grant_type")
		if grantType != "authorization_code" {
			writeTokenError(w, oauth2.NewError(oauth2.ErrorUnsupportedGrantType), state)
			return
		}

		code := r.PostForm.Get("code")
		if code == "" {
			writeTokenError(w, oauth2.NewError(oauth2.ErrorInvalidRequest), state)
			return
		}

		user, password, ok := phttp.BasicAuth(r)
		if !ok {
			writeTokenError(w, oauth2.NewError(oauth2.ErrorInvalidClient), state)
			return
		}

		ci := oauth2.ClientIdentity{ID: user, Secret: password}
		jwt, err := srv.Token(ci, code)
		if err != nil {
			writeTokenError(w, err, state)
			return
		}

		t := oAuth2Token{
			AccessToken: jwt.Encode(),
			IDToken:     jwt.Encode(),
			TokenType:   "bearer",
		}

		b, err := json.Marshal(t)
		if err != nil {
			log.Printf("Failed marshaling %#v to JSON: %v", t, err)
			writeTokenError(w, oauth2.NewError(oauth2.ErrorServerError), state)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

type oAuth2Token struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

type oAuth2ErrorResponse struct {
	Error string `json:"error"`
	State string `json:"state,omitempty"`
}

func writeTokenError(w http.ResponseWriter, err error, state string) {
	oerr, ok := err.(*oauth2.Error)
	if !ok {
		oerr = oauth2.NewError(oauth2.ErrorServerError)
	}

	var status int
	switch oerr.Type {
	case oauth2.ErrorInvalidClient:
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", "Basic")
	default:
		status = http.StatusBadRequest
	}

	r := &oAuth2ErrorResponse{Error: oerr.Type, State: state}
	b, err := json.Marshal(r)
	if err != nil {
		log.Printf("Failed marshaling OAuth2 error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func writeAuthError(w http.ResponseWriter, err error, state string) {
	oerr, ok := err.(*oauth2.Error)
	if !ok {
		oerr = oauth2.NewError(oauth2.ErrorServerError)
	}

	r := &oAuth2ErrorResponse{Error: oerr.Type, State: state}
	b, err := json.Marshal(r)
	if err != nil {
		log.Printf("Failed marshaling OAuth2 error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(b)
}

func redirectAuthError(w http.ResponseWriter, err error, state string, redirectURL url.URL) {
	oerr, ok := err.(*oauth2.Error)
	if !ok {
		oerr = oauth2.NewError(oauth2.ErrorServerError)
	}

	q := redirectURL.Query()
	q.Set("error", oerr.Type)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}
