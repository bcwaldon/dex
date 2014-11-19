package server

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/session"
)

type OIDCServer interface {
	Client(string) *oauth2.ClientIdentity
	NewSession(oauth2.ClientIdentity, string) (string, error)
	Login(oidc.Identity, string) (string, error)
	Token(oauth2.ClientIdentity, string) (*jose.JWT, error)
	KillSession(string) error
}

type Server struct {
	IssuerURL          string
	KeyManager         key.PrivateKeyManager
	SessionManager     *session.SessionManager
	ClientIdentityRepo ClientIdentityRepo
}

func (s *Server) KillSession(sessionKey string) error {
	sessionID, err := s.SessionManager.ExchangeKey(sessionKey)
	if err != nil {
		return err
	}

	_, err = s.SessionManager.Kill(sessionID)
	return err
}

func (s *Server) ProviderConfig() oidc.ProviderConfig {
	cfg := oidc.ProviderConfig{
		Issuer: s.IssuerURL,

		AuthEndpoint:  s.IssuerURL + HttpPathAuth,
		TokenEndpoint: s.IssuerURL + httpPathToken,
		KeysEndpoint:  s.IssuerURL + httpPathKeys,

		GrantTypesSupported:               []string{"authorization_code"},
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenAlgValuesSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}

	return cfg
}

func (s *Server) HTTPHandler(idpcs map[string]connector.IDPConnector, tpl *template.Template) http.Handler {
	clock := clockwork.NewRealClock()
	mux := http.NewServeMux()
	mux.HandleFunc(httpPathDiscovery, handleDiscoveryFunc(s.ProviderConfig()))
	mux.HandleFunc(HttpPathAuth, handleAuthFunc(s, idpcs, tpl))
	mux.HandleFunc(httpPathToken, handleTokenFunc(s))
	mux.HandleFunc(httpPathKeys, handleKeysFunc(s.KeyManager, clock))

	pcfg := s.ProviderConfig()
	for id, idpc := range idpcs {
		errorURL, err := url.Parse(fmt.Sprintf("%s?idpc_id=%s", pcfg.AuthEndpoint, id))
		if err != nil {
			log.Fatal(err)
		}
		idpc.Register(mux, *errorURL)
	}

	return mux
}

func (s *Server) Client(clientID string) *oauth2.ClientIdentity {
	return s.ClientIdentityRepo.ClientIdentity(clientID)
}

func (s *Server) NewSession(ci oauth2.ClientIdentity, state string) (string, error) {
	sessionID, err := s.SessionManager.NewSession(ci, state)
	if err != nil {
		return "", err
	}

	log.Printf("Session %s created: clientID=%s state=%s", sessionID, ci.ID, state)
	return s.SessionManager.NewSessionKey(sessionID)
}

func (s *Server) Login(ident oidc.Identity, key string) (string, error) {
	sessionID, err := s.SessionManager.ExchangeKey(key)
	if err != nil {
		return "", err
	}

	ses, err := s.SessionManager.Identify(sessionID, ident)
	if err != nil {
		return "", err
	}

	log.Printf("Session %s identified: clientID=%s identity=%#v", sessionID, ses.ClientIdentity.ID, ident)

	code, err := s.SessionManager.NewSessionKey(sessionID)
	if err != nil {
		return "", err
	}

	ru := ses.ClientIdentity.RedirectURL
	q := ru.Query()
	q.Set("code", code)
	q.Set("state", ses.ClientState)
	ru.RawQuery = q.Encode()

	return ru.String(), nil
}

func (s *Server) Token(ci oauth2.ClientIdentity, key string) (*jose.JWT, error) {
	exist := s.ClientIdentityRepo.ClientIdentity(ci.ID)
	if exist == nil || exist.Secret != ci.Secret {
		return nil, oauth2.NewError(oauth2.ErrorInvalidClient)
	}

	sessionID, err := s.SessionManager.ExchangeKey(key)
	if err != nil {
		return nil, oauth2.NewError(oauth2.ErrorInvalidGrant)
	}

	ses, err := s.SessionManager.Kill(sessionID)
	if err != nil {
		return nil, oauth2.NewError(oauth2.ErrorInvalidRequest)
	}

	if !ses.ClientIdentity.Match(ci) {
		return nil, oauth2.NewError(oauth2.ErrorInvalidGrant)
	}

	signer, err := s.KeyManager.Signer()
	if err != nil {
		log.Printf("Failed to generate ID token: %v", err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	}

	jwt, err := josesig.NewSignedJWT(ses.Claims(s.IssuerURL), signer)
	if err != nil {
		log.Printf("Failed to generate ID token: %v", err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	}

	log.Printf("Session %s token sent: clientID=%s", sessionID, ci.ID)

	return jwt, nil
}
