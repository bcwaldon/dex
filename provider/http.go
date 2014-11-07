package provider

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos-inc/auth/jose"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

var (
	HTTPPathDiscovery = "/.well-known/openid-configuration"
	HTTPPathAuth      = "/auth"
	HTTPPathToken     = "/token"
	HTTPPathRevoke    = "/revoke"
	HTTPPathUserInfo  = "/user"
	HTTPPathKeys      = "/keys" // a.k.a. JWKS
)

func NewHTTPHandler(p Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(HTTPPathDiscovery, handleDiscoveryFunc(p))
	mux.HandleFunc(HTTPPathAuth, handleAuthFunc(p))
	mux.HandleFunc(HTTPPathToken, handleTokenFunc(p))
	mux.HandleFunc(HTTPPathKeys, handleKeysFunc(p))
	return mux
}

func handleDiscoveryFunc(p Provider) http.HandlerFunc {
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

func handleKeysFunc(p Provider) http.HandlerFunc {
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

func handleAuthFunc(p Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rt := r.URL.Query().Get("response_type"); rt != "code" {
			msg := fmt.Sprintf("response_type %q unsupported", rt)
			phttp.WriteError(w, http.StatusBadRequest, msg)
			return
		}

		redirectURI := r.URL.Query().Get("redirect_uri")
		if redirectURI == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing redirect_uri query param")
			return
		}

		ru, err := url.Parse(redirectURI)
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, "redirect_uri query param invalid")
			return
		}

		scope := strings.Split(r.URL.Query().Get("scope"), " ")
		if len(scope) == 0 {
			phttp.WriteError(w, http.StatusBadRequest, "requested empty scope")
			return
		}

		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing client_id query param")
			return
		}

		userID := r.URL.Query().Get("uid")
		if userID == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing uid query param")
			return
		}

		u := p.User(userID)
		if u == nil {
			phttp.WriteError(w, http.StatusBadRequest, "unrecognized user ID")
			return
		}

		c := p.Client(clientID)
		if c == nil {
			phttp.WriteError(w, http.StatusBadRequest, "unrecognized client ID")
			return
		}

		code := p.NewSession(*c, *u)

		q := ru.Query()
		q.Set("code", code)
		ru.RawQuery = q.Encode()
		w.Header().Set("Location", ru.String())
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
}

func handleTokenFunc(p Provider) http.HandlerFunc {
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

		c := p.Client(clientID)
		if c == nil || c.Secret != clientSecret {
			w.Header().Set("WWW-Authenticate", "Basic")
			phttp.WriteError(w, http.StatusUnauthorized, "unrecognized client")
			return
		}

		ses := p.Session(code)
		if ses == nil {
			phttp.WriteError(w, http.StatusBadRequest, "unrecognized auth code")
			return
		}

		id, err := ses.IDToken(p.Config().IssuerURL, p.Signer())
		if err != nil {
			log.Printf("Failed marshaling ID token to JSON: %v", err)
			phttp.WriteError(w, http.StatusInternalServerError, "unable to marshal id token")
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
			IDToken:      id.Encode(),
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
