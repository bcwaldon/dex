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
	httpPathRevoke    = "/revoke"
	httpPathUserInfo  = "/user"
	httpPathKeys      = "/keys" // a.k.a. JWKS
	HttpPathAuthIDPC  = "/auth/idpc"
)

func handleDiscoveryFunc(cfg oidc.ProviderConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

func handleAuthFunc(sm *SessionManager, ciRepo ClientIdentityRepo, idpc connector.IDPConnector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET only acceptable method")
			return
		}

		acr, err := oauth2.ParseAuthCodeRequest(r)
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		if ciRepo.ClientIdentity(acr.ClientID) == nil {
			phttp.WriteError(w, http.StatusBadRequest, "unrecognized client ID")
			return
		}

		w.Header().Set("Location", idpc.LoginURL(r))
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
}

func handleTokenFunc(sm *SessionManager, ciRepo ClientIdentityRepo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			msg := fmt.Sprintf("POST only supported method")
			phttp.WriteError(w, http.StatusMethodNotAllowed, msg)
			return
		}

		err := r.ParseForm()
		if err != nil {
			msg := fmt.Sprintf("unable to parse form from body: %v", err)
			phttp.WriteError(w, http.StatusBadRequest, msg)
			return
		}

		grantType := r.Form.Get("grant_type")
		if grantType != "authorization_code" {
			phttp.WriteError(w, http.StatusBadRequest, "grant_type must be 'authorization_code'")
			return
		}

		code := r.Form.Get("code")
		if code == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing code field")
			return
		}

		clientID, clientSecret, ok := phttp.BasicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Basic")
			phttp.WriteError(w, http.StatusUnauthorized, "client authentication required")
		}

		c := ciRepo.ClientIdentity(clientID)
		if c == nil || c.Secret != clientSecret {
			w.Header().Set("WWW-Authenticate", "Basic")
			phttp.WriteError(w, http.StatusUnauthorized, "unrecognized client")
			return
		}

		ses := sm.LookupByAuthCode(code)
		if ses == nil {
			phttp.WriteError(w, http.StatusBadRequest, "unrecognized auth code")
			return
		}

		t := struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			Expiry       int    `json:"expiry"`
			IDToken      string `json:"id_token"`
		}{
			AccessToken:  ses.AccessToken,
			RefreshToken: ses.RefreshToken,
			IDToken:      ses.IDToken.Encode(),
		}
		b, err := json.Marshal(t)
		if err != nil {
			log.Printf("Failed marshaling %#v to JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}
