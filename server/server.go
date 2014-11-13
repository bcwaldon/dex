package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

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
	mux.HandleFunc(httpPathToken, handleTokenFunc(s.SessionManager, s.ClientIdentityRepo))
	mux.HandleFunc(httpPathKeys, handleKeysFunc([]jose.JWK{s.Signer.JWK()}))
	idpc.Register(mux)
	return mux
}

func (s *Server) Login(ident oidc.Identity, sessionKey string) (string, error) {
	ses := s.SessionManager.Session(sessionKey)
	if ses == nil {
		return "", fmt.Errorf("unrecognized session %q", sessionKey)
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
