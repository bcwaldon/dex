package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos-inc/auth/oidc"
)

var (
	staticKeyID = "2b3390f656ff335d6fdb8dfe117748c9f2709c02"

	pathDiscovery = "/.well-known/openid-configuration"
	pathAuth      = "/auth"
	pathToken     = "/token"
	pathRevoke    = "/revoke"
	pathUserInfo  = "/user"
	pathKeys      = "/keys" // a.k.a. JWKS
)

type Session struct {
	AuthCode     string
	SubjectID    string
	ClientID     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	AccessToken  string
	RefreshToken string
}

func (ses *Session) IDToken(issuerURL string, signer oidc.Signer) (*oidc.JWT, error) {
	claims := map[string]interface{}{
		// required
		"iss": issuerURL,
		"sub": ses.SubjectID,
		"aud": ses.ClientID,
		// explicitly cast to float64 for consistent JSON (de)serialization
		"exp": float64(ses.ExpiresAt.Unix()),
		"iat": float64(ses.IssuedAt.Unix()),

		// conventional
		"name":  "Elroy",
		"email": "elroy@example.com",
	}

	return oidc.NewSignedJWT(claims, signer)
}

func NewSessionManager() *SessionManager {
	return &SessionManager{make(map[string]*Session)}
}

type SessionManager struct {
	sessions map[string]*Session
}

func (m *SessionManager) NewSession(clientID string) string {
	now := time.Now().UTC()
	s := Session{
		AuthCode:     genToken(),
		SubjectID:    genToken(),
		ClientID:     clientID,
		IssuedAt:     now,
		ExpiresAt:    now.Add(30 * time.Second),
		AccessToken:  genToken(),
		RefreshToken: genToken(),
	}
	m.sessions[s.AuthCode] = &s
	return s.AuthCode
}

func (m *SessionManager) LookupByAuthCode(code string) *Session {
	return m.sessions[code]
}

func genToken() string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(mrand.Int63()))
	return base64.URLEncoding.EncodeToString(b)
}

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

	srv := Server{
		IssuerName:     *issuerName,
		IssuerURL:      *listen,
		Signer:         signer,
		SessionManager: NewSessionManager(),
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
	IssuerName     string
	IssuerURL      string
	Signer         oidc.Signer
	SessionManager *SessionManager
}

func (s *Server) ProviderConfig() oidc.ProviderConfig {
	cfg := oidc.ProviderConfig{
		Issuer: s.IssuerName,

		AuthEndpoint:       s.IssuerURL + pathAuth,
		TokenEndpoint:      s.IssuerURL + pathToken,
		UserInfoEndpoint:   s.IssuerURL + pathUserInfo,
		RevocationEndpoint: s.IssuerURL + pathRevoke,
		JWKSURI:            s.IssuerURL + pathKeys,

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

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		writeError(w, http.StatusBadRequest, "missing client_id query param")
		return
	}

	code := s.SessionManager.NewSession(clientID)

	q := ru.Query()
	q.Set("code", code)
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

	code := r.Form.Get("code")
	if len(code) == 0 {
		writeError(w, http.StatusBadRequest, "auth code must be provided")
		return
	}

	ses := s.SessionManager.LookupByAuthCode(code)
	if ses == nil {
		writeError(w, http.StatusForbidden, "unknown auth code")
		return
	}

	id, err := ses.IDToken(s.IssuerURL, s.Signer)
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

func generateRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(crand.Reader, 1024)
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
