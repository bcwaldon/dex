package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

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
			phttp.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		key, err := srv.NewSession(*acr)
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		lu, err := idpc.LoginURL(key)
		if err != nil {
			log.Printf("IDPConnector.LoginURL failed: %v", err)
			phttp.WriteError(w, http.StatusInternalServerError, "")
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
			phttp.WriteError(w, http.StatusBadRequest, oauth2.ErrorInvalidRequest)
			return
		}

		state := r.PostForm.Get("code")

		grantType := r.PostForm.Get("grant_type")
		if grantType != "authorization_code" {
			writeOAuth2Error(w, oauth2.NewError(oauth2.ErrorUnsupportedGrantType), state)
			return
		}

		code := r.PostForm.Get("code")
		if code == "" {
			writeOAuth2Error(w, oauth2.NewError(oauth2.ErrorInvalidRequest), state)
			return
		}

		user, password, ok := phttp.BasicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Basic")
			writeOAuth2Error(w, oauth2.NewError(oauth2.ErrorInvalidClient), state)
			return
		}

		ci := oauth2.ClientIdentity{ID: user, Secret: password}
		jwt, err := srv.Token(ci, code)
		if err != nil {
			if oerr, ok := err.(*oauth2.Error); ok {
				writeOAuth2Error(w, oerr, state)
			} else {
				phttp.WriteError(w, http.StatusInternalServerError, "")
			}
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
			writeOAuth2Error(w, oauth2.NewError(oauth2.ErrorServerError), state)
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

func writeOAuth2Error(w http.ResponseWriter, oerr *oauth2.Error, state string) {
	status := http.StatusBadRequest
	if oerr.Type == oauth2.ErrorInvalidClient {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", "Basic")
	}
	w.Header().Set("Content-Type", "application/json")

	s := struct {
		Error string `json:"error"`
		State string `json:"state,omitempty"`
	}{
		Error: oerr.Type,
		State: state,
	}

	w.WriteHeader(status)

	b, err := json.Marshal(s)
	if err != nil {
		log.Printf("Failed marshaling OAuth2 error: %v", err)
		return
	}

	w.Write(b)
}
