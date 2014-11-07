package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/provider"
)

var (
	staticKeyID = "2b3390f656ff335d6fdb8dfe117748c9f2709c02"
)

func main() {
	issuerName := flag.String("issuer-name", "example", "")
	listen := flag.String("listen", "http://localhost:5556", "")
	uFile := flag.String("users", "./fixtures/users.json", "json file containing set of users")
	cFile := flag.String("clients", "./fixtures/clients.json", "json file containing set of clients")
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

	uf, err := os.Open(*uFile)
	if err != nil {
		log.Fatalf("Unable to read users from file %q: %v", *uFile, err)
	}
	defer uf.Close()
	idp, err := provider.NewIdentityProviderFromReader(uf)
	if err != nil {
		log.Fatalf("Unable to build local identity provider from file %q: %v", *uFile, err)
	}

	cf, err := os.Open(*cFile)
	if err != nil {
		log.Fatalf("Unable to read clients from file %s: %v", *cFile, err)
	}
	defer cf.Close()
	cRepo, err := provider.NewClientRepoFromReader(cf)
	if err != nil {
		log.Fatalf("Unable to read clients from file %s: %v", *cFile, err)
	}

	srv := Server{
		issuerName:     *issuerName,
		issuerURL:      *listen,
		signer:         signer,
		sessionManager: provider.NewSessionManager(),
		idProvider:     idp,
		clientRepo:     cRepo,
	}
	hdlr := provider.NewHTTPHandler(&srv)
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
	sessionManager *provider.SessionManager
	idProvider     provider.IdentityProvider
	clientRepo     provider.ClientRepo
}

func (s *Server) NewSession(c provider.Client, u provider.User) string {
	return s.sessionManager.NewSession(c, u)
}

func (s *Server) Session(code string) *provider.Session {
	return s.sessionManager.LookupByAuthCode(code)
}

func (s *Server) User(userID string) *provider.User {
	return s.idProvider.User(userID)
}

func (s *Server) Client(clientID string) *provider.Client {
	return s.clientRepo.Client(clientID)
}

func (s *Server) Config() oidc.ProviderConfig {
	cfg := oidc.ProviderConfig{
		Issuer:    s.issuerName,
		IssuerURL: s.issuerURL,

		AuthEndpoint:       s.issuerURL + provider.HTTPPathAuth,
		TokenEndpoint:      s.issuerURL + provider.HTTPPathToken,
		UserInfoEndpoint:   s.issuerURL + provider.HTTPPathUserInfo,
		RevocationEndpoint: s.issuerURL + provider.HTTPPathRevoke,
		JWKSURI:            s.issuerURL + provider.HTTPPathKeys,

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
