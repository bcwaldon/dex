package server

import (
	"encoding/json"
	"fmt"
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
	httpPathAuth      = "/auth"
	httpPathToken     = "/token"
	httpPathKeys      = "/keys"
	HttpPathAuthIDPC  = "/auth/idpc"
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

func handleAuthFunc(srv OIDCServer, idpc connector.IDPConnector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET only acceptable method")
			return
		}

		acr, err := oauth2.ParseAuthCodeRequest(r.URL.Query())
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
			msg := fmt.Sprintf("unable to parse form from body: %v", err)
			phttp.WriteError(w, http.StatusBadRequest, msg)
			return
		}

		grantType := r.PostForm.Get("grant_type")
		if grantType != "authorization_code" {
			phttp.WriteError(w, http.StatusBadRequest, "grant_type must be 'authorization_code'")
			return
		}

		code := r.PostForm.Get("code")
		if code == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing code field")
			return
		}

		user, password, ok := phttp.BasicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Basic")
			phttp.WriteError(w, http.StatusUnauthorized, "need to authenticate client")
			return
		}

		ci := oauth2.ClientIdentity{ID: user, Secret: password}
		jwt, err := srv.Token(ci, code)
		if err != nil {
			var status int
			switch err {
			case oauth2.ErrorInvalidClient:
				status = http.StatusUnauthorized
				w.Header().Set("WWW-Authenticate", "Basic")
			case oauth2.ErrorInvalidGrant:
				status = http.StatusBadRequest
			default:
				status = http.StatusInternalServerError
			}

			phttp.WriteError(w, status, err.Error())
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
			phttp.WriteError(w, http.StatusInternalServerError, "")
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
