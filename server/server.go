package server

import (
	"net/http"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oidc"
)

type Server struct {
	IssuerURL          string
	Signer             josesig.Signer
	SessionManager     *SessionManager
	ClientIdentityRepo ClientIdentityRepo
	IDPConnector       connector.IDPConnector
}

func (s *Server) ProviderConfig() oidc.ProviderConfig {
	cfg := oidc.ProviderConfig{
		Issuer: s.IssuerURL,

		AuthEndpoint:       s.IssuerURL + httpPathAuth,
		TokenEndpoint:      s.IssuerURL + httpPathToken,
		UserInfoEndpoint:   s.IssuerURL + httpPathUserInfo,
		RevocationEndpoint: s.IssuerURL + httpPathRevoke,
		JWKSURI:            s.IssuerURL + httpPathKeys,

		// google supports these:
		//ResponseTypesSupported:            []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"},

		ResponseTypesSupported:            []string{"id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenAlgValuesSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}

	return cfg
}

func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(httpPathDiscovery, handleDiscoveryFunc(s.ProviderConfig()))
	mux.HandleFunc(httpPathAuth, handleAuthFunc(s.SessionManager, s.ClientIdentityRepo, s.IDPConnector))
	mux.HandleFunc(httpPathToken, handleTokenFunc(s.SessionManager, s.ClientIdentityRepo))
	mux.HandleFunc(httpPathKeys, handleKeysFunc([]jose.JWK{s.Signer.JWK()}))
	return mux
}
