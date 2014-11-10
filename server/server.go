package server

import (
	"log"
	"net/http"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
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

func (s *Server) HTTPHandler(idpc connector.IDPConnector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(httpPathDiscovery, handleDiscoveryFunc(s.ProviderConfig()))
	mux.HandleFunc(httpPathAuth, handleAuthFunc(s.SessionManager, s.ClientIdentityRepo, idpc))
	mux.HandleFunc(httpPathToken, handleTokenFunc(s.SessionManager, s.ClientIdentityRepo))
	mux.HandleFunc(httpPathKeys, handleKeysFunc([]jose.JWK{s.Signer.JWK()}))
	idpc.Register(mux)
	return mux
}

func (s *Server) Login(w http.ResponseWriter, acr oauth2.AuthCodeRequest, ident oidc.Identity) {
	ci := s.ClientIdentityRepo.ClientIdentity(acr.ClientID)
	if ci == nil {
		phttp.WriteError(w, http.StatusBadRequest, "unrecognized client ID")
		return
	}

	code, err := s.SessionManager.NewSession(*ci, ident)
	if err != nil {
		log.Printf("Failed creating session: %v", err)
		phttp.WriteError(w, http.StatusInternalServerError, "")
		return
	}

	q := acr.RedirectURL.Query()
	q.Set("code", code)
	acr.RedirectURL.RawQuery = q.Encode()
	w.Header().Set("Location", acr.RedirectURL.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}
