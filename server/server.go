package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

type OIDCServer interface {
	NewSession(oauth2.AuthCodeRequest) (string, error)
	Login(oidc.Identity, string) (string, error)
	Token(oauth2.ClientIdentity, string) (*jose.JWT, error)
}

type Server struct {
	IssuerURL          string
	Signer             josesig.Signer
	SessionManager     *SessionManager
	ClientIdentityRepo ClientIdentityRepo
}

func (s *Server) ProviderConfig() oidc.ProviderConfig {
	cfg := oidc.ProviderConfig{
		Issuer: s.IssuerURL,

		AuthEndpoint:  s.IssuerURL + httpPathAuth,
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

func (s *Server) HTTPHandler(idpc connector.IDPConnector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(httpPathDiscovery, handleDiscoveryFunc(s.ProviderConfig()))
	mux.HandleFunc(httpPathAuth, handleAuthFunc(s, idpc))
	mux.HandleFunc(httpPathToken, handleTokenFunc(s))
	mux.HandleFunc(httpPathKeys, handleKeysFunc([]jose.JWK{s.Signer.JWK()}))
	idpc.Register(mux)
	return mux
}

func (s *Server) NewSession(acr oauth2.AuthCodeRequest) (key string, err error) {
	ci := s.ClientIdentityRepo.ClientIdentity(acr.ClientID)
	if ci == nil {
		err = errors.New("unrecognized client ID")
		return
	}

	ses := s.SessionManager.NewSession(*ci, acr.State)
	key = ses.NewKey()

	return
}

func (s *Server) Login(ident oidc.Identity, key string) (string, error) {
	ses := s.SessionManager.Session(key)
	if ses == nil {
		return "", fmt.Errorf("unrecognized session %q", key)
	}

	err := ses.Identify(ident)
	if err != nil {
		return "", err
	}

	code := ses.NewKey()
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
		return nil, errors.New("unrecognized client")
	}

	ses := s.SessionManager.Session(key)
	if ses == nil {
		return nil, errors.New("invalid_grant")
	}

	if !ses.ClientIdentity.Match(ci) {
		return nil, errors.New("invalid_grant")
	}

	jwt, err := ses.IDToken()
	if err != nil {
		log.Printf("Failed to generate ID token: %v", err)
		return nil, errors.New("server_error")
	}

	return jwt, nil
}
