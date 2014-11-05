package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oidc"
	oidchttp "github.com/coreos-inc/auth/oidc/http"
)

var (
	staticKeyID = "2b3390f656ff335d6fdb8dfe117748c9f2709c02"
)

func NewSessionManager() *SessionManager {
	return &SessionManager{make(map[string]*oidc.Session)}
}

type SessionManager struct {
	sessions map[string]*oidc.Session
}

func (m *SessionManager) NewSession(clientID string) string {
	now := time.Now().UTC()
	s := oidc.Session{
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

func (m *SessionManager) LookupByAuthCode(code string) *oidc.Session {
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

	signer := josesig.NewSignerRSA(staticKeyID, *privKey)

	srv := Server{
		issuerName:     *issuerName,
		issuerURL:      *listen,
		signer:         signer,
		sessionManager: NewSessionManager(),
	}
	hdlr := oidchttp.NewProviderHandler(&srv)
	httpsrv := &http.Server{
		Addr:    fmt.Sprintf(":%s", p),
		Handler: hdlr,
	}

	log.Printf("binding to %s...", httpsrv.Addr)
	log.Fatal(httpsrv.ListenAndServe())
}

type Server struct {
	issuerName     string
	issuerURL      string
	signer         josesig.Signer
	sessionManager *SessionManager
}

func (s *Server) NewSession(clientID string) string {
	return s.sessionManager.NewSession(clientID)
}

func (s *Server) LookupSession(code string) *oidc.Session {
	return s.sessionManager.LookupByAuthCode(code)
}

func (s *Server) Config() oidc.ProviderConfig {
	cfg := oidc.ProviderConfig{
		Issuer:    s.issuerName,
		IssuerURL: s.issuerURL,

		AuthEndpoint:       s.issuerURL + oidchttp.PathAuth,
		TokenEndpoint:      s.issuerURL + oidchttp.PathToken,
		UserInfoEndpoint:   s.issuerURL + oidchttp.PathUserInfo,
		RevocationEndpoint: s.issuerURL + oidchttp.PathRevoke,
		JWKSURI:            s.issuerURL + oidchttp.PathKeys,

		// google supports these:
		//ResponseTypesSupported:            []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"},

		ResponseTypesSupported:            []string{"id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenAlgValuesSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}

	return cfg
}

func (s *Server) Signer() josesig.Signer {
	return s.signer
}

func (s *Server) PublicKeys() []jose.JWK {
	return []jose.JWK{s.signer.JWK()}
}

func generateRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(crand.Reader, 1024)
}
