package http

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oidc"
)

var (
	PathDiscovery = "/.well-known/openid-configuration"
	PathAuth      = "/auth"
	PathToken     = "/token"
	PathRevoke    = "/revoke"
	PathUserInfo  = "/user"
	PathKeys      = "/keys" // a.k.a. JWKS
)

func NewProviderHandler(p oidc.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(PathDiscovery, handleDiscoveryFunc(p))
	mux.HandleFunc(PathAuth, handleAuthFunc(p))
	mux.HandleFunc(PathToken, handleTokenFunc(p))
	mux.HandleFunc(PathKeys, handleKeysFunc(p))
	return mux
}

func handleDiscoveryFunc(p oidc.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := p.Config()
		b, err := json.Marshal(cfg)
		if err != nil {
			log.Printf("Unable to marshal %#v to JSON: %v", cfg, err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
}

func handleKeysFunc(p oidc.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys := struct {
			Keys []jose.JWK `json:"keys"`
		}{
			Keys: p.PublicKeys(),
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

func handleAuthFunc(p oidc.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		if redirectURI == "" {
			writeError(w, http.StatusBadRequest, "missing redirect_uri query param")
			return
		}

		ru, err := url.Parse(redirectURI)
		if err != nil {
			writeError(w, http.StatusBadRequest, "redirect_uri query param invalid")
			return
		}

		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			writeError(w, http.StatusBadRequest, "missing client_id query param")
			return
		}

		code := p.NewSession(clientID)

		q := ru.Query()
		q.Set("code", code)
		ru.RawQuery = q.Encode()
		w.Header().Set("Location", ru.String())
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
}

func handleTokenFunc(p oidc.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		code := r.Form.Get("code")
		if len(code) == 0 {
			writeError(w, http.StatusBadRequest, "auth code must be provided")
			return
		}

		ses := p.LookupSession(code)
		if ses == nil {
			writeError(w, http.StatusForbidden, "unknown auth code")
			return
		}

		id, err := ses.IDToken(p.Config().IssuerURL, p.Signer())
		if err != nil {
			log.Printf("Failed marshaling ID token to JSON: %v", err)
			writeError(w, http.StatusInternalServerError, "unable to marshal id token")
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
			IDToken:      id.SignedData(),
		}
		b, _ := json.Marshal(t)
		if err != nil {
			log.Printf("Failed marshaling %#v to JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	e := struct {
		Error string `json:"error"`
	}{
		Error: msg,
	}
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("Failed marshaling %#v to JSON: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}
