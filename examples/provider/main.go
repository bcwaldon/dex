package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
)

var (
	staticAuthCode     = "pants"
	staticAccessToken  = "RsT5OjbzRn430zqMLgV3Ia"
	staticRefreshToken = "StU5OjbzRn430zqMLgV3Ib"

	staticKeyID  = "2b3390f656ff335d6fdb8dfe117748c9f2709c02"
	staticClaims = map[string]string{
		"name":  "Elroy",
		"email": "elroy@example.com",
	}

	pathDiscovery = "/.well-known/openid-configuration"
	pathAuth      = "/auth"
	pathToken     = "/token"
	pathRevoke    = "/revoke"
	pathUserInfo  = "/user"
	pathKeys      = "/keys" // a.k.a. JWKS
)

func main() {
	issuerName := flag.String("issuer-name", "example", "")
	listen := flag.String("listen", "http://localhost:5556", "")
	flag.Parse()

	l, err := url.Parse(*listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	_, p, err := net.SplitHostPort(l.Host)
	if err != nil {
		log.Fatalf("Unable to parse host from --listen flag: %v", err)
	}

	privKey, err := generateRSAPrivateKey()
	if err != nil {
		log.Fatalf("Unable to generate RSA private key: %v", err)
	}

	signer := oidc.NewSignerRSA(staticKeyID, *privKey)

	staticJWT, err := oidc.NewSignedJWT(staticClaims, signer)
	if err != nil {
		log.Fatalf("Failed signing static JWT: %v", err)
	}

	srv := Server{
		IssuerName: *issuerName,
		ServiceURL: *listen,
		Signer:     signer,
		JWT:        *staticJWT,
	}

	http.HandleFunc(pathDiscovery, srv.handleDiscovery)
	http.HandleFunc(pathAuth, srv.handleAuth)
	http.HandleFunc(pathToken, srv.handleToken)
	http.HandleFunc(pathKeys, srv.handleKeys)

	bind := fmt.Sprintf(":%s", p)
	log.Printf("binding to %s...", bind)
	log.Fatal(http.ListenAndServe(bind, nil))
}

type Server struct {
	IssuerName string
	ServiceURL string
	Signer     oidc.Signer
	JWT        oidc.JWT
}

func (s *Server) ProviderConfig() oidc.ProviderConfig {
	cfg := oidc.ProviderConfig{
		Issuer: s.IssuerName,

		AuthEndpoint:       s.ServiceURL + pathAuth,
		TokenEndpoint:      s.ServiceURL + pathToken,
		UserInfoEndpoint:   s.ServiceURL + pathUserInfo,
		RevocationEndpoint: s.ServiceURL + pathRevoke,
		JWKSURI:            s.ServiceURL + pathKeys,

		// google supports these:
		//ResponseTypesSupported:            []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"},

		ResponseTypesSupported:            []string{"id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenAlgValuesSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}

	return cfg
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	cfg := s.ProviderConfig()
	b, err := json.Marshal(cfg)
	if err != nil {
		log.Printf("Unable to marshal %#v to JSON: %v", cfg, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	keys := struct {
		Keys []oidc.JWK `json:"keys"`
	}{
		Keys: []oidc.JWK{s.Signer.JWK()},
	}

	b, err := json.Marshal(keys)
	if err != nil {
		log.Printf("Unable to marshal signing key to JSON: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
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

	q := ru.Query()
	q.Set("code", staticAuthCode)
	ru.RawQuery = q.Encode()
	w.Header().Set("Location", ru.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
	return
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authCode := r.Form.Get("code")
	if authCode != staticAuthCode {
		//TODO(bcwaldon): determine what status code to use here
		writeError(w, http.StatusForbidden, "auth code unrecognized")
		return
	}

	t := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Expiry       int    `json:"expiry"`
		IDToken      string `json:"id_token"`
	}{
		AccessToken:  staticAccessToken,
		RefreshToken: staticRefreshToken,
		IDToken:      s.JWT.SignedData(),
	}
	b, _ := json.Marshal(t)
	if err != nil {
		log.Printf("Failed marshaling %#v to JSON: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func generateRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
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
