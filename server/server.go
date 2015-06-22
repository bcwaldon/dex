package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"sort"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/email"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
	"github.com/coreos/pkg/health"
)

const (
	LoginPageTemplateName   = "login.html"
	RegisterTemplateName    = "register.html"
	VerifyEmailTemplateName = "verify-email.html"

	APIVersion = "v1"
)

type OIDCServer interface {
	ClientMetadata(string) (*oidc.ClientMetadata, error)
	NewSession(connectorID, clientID, clientState string, redirectURL url.URL, register bool) (string, error)
	Login(oidc.Identity, string) (string, error)
	CodeToken(creds oidc.ClientCredentials, sessionKey string) (*jose.JWT, error)
	ClientCredsToken(creds oidc.ClientCredentials) (*jose.JWT, error)
	KillSession(string) error
}

type Server struct {
	IssuerURL           url.URL
	KeyManager          key.PrivateKeyManager
	KeySetRepo          key.PrivateKeySetRepo
	SessionManager      *session.SessionManager
	ClientIdentityRepo  ClientIdentityRepo
	ConnectorConfigRepo connector.ConnectorConfigRepo
	Templates           *template.Template
	LoginTemplate       *template.Template
	RegisterTemplate    *template.Template
	VerifyEmailTemplate *template.Template
	HealthChecks        []health.Checkable
	Connectors          []connector.Connector
	UserRepo            user.UserRepo
	UserManager         *user.Manager
	PasswordInfoRepo    user.PasswordInfoRepo
	Emailer             *email.TemplatizedEmailer
}

func (s *Server) Run() chan struct{} {
	stop := make(chan struct{})

	chans := []chan struct{}{
		key.NewKeySetSyncer(s.KeySetRepo, s.KeyManager).Run(),
	}

	for _, idpc := range s.Connectors {
		chans = append(chans, idpc.Sync())
	}

	go func() {
		<-stop
		for _, ch := range chans {
			close(ch)
		}
	}()

	return stop
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
	iss := s.IssuerURL.String()
	cfg := oidc.ProviderConfig{
		Issuer: iss,

		AuthEndpoint:  iss + httpPathAuth,
		TokenEndpoint: iss + httpPathToken,
		KeysEndpoint:  iss + httpPathKeys,

		GrantTypesSupported:               []string{oauth2.GrantTypeAuthCode, oauth2.GrantTypeClientCreds},
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenAlgValuesSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}

	return cfg
}

func (s *Server) absURL(paths ...string) url.URL {
	url := s.IssuerURL
	paths = append([]string{url.Path}, paths...)
	url.Path = path.Join(paths...)
	return url
}

func (s *Server) AddConnector(cfg connector.ConnectorConfig) error {
	connectorID := cfg.ConnectorID()
	ns := s.IssuerURL
	ns.Path = path.Join(ns.Path, httpPathAuth, connectorID)

	idpc, err := cfg.Connector(ns, s.Login, s.Templates)
	if err != nil {
		return err
	}

	s.Connectors = append(s.Connectors, idpc)

	sortable := sortableIDPCs(s.Connectors)
	sort.Sort(sortable)

	// We handle the LocalConnector specially because it needs access to the
	// UserRepo and the PasswordInfoRepo; if it turns out that other connectors
	// need access to these resources we'll figure out how to provide it in a
	// cleaner manner.
	localConn, ok := idpc.(*connector.LocalConnector)
	if ok {
		if s.UserRepo == nil {
			return errors.New("UserRepo cannot be nil")
		}

		if s.PasswordInfoRepo == nil {
			return errors.New("PasswordInfoRepo cannot be nil")
		}

		localConn.SetLocalIdentityProvider(&connector.LocalIdentityProvider{
			UserRepo:         s.UserRepo,
			PasswordInfoRepo: s.PasswordInfoRepo,
		})

		localCfg, ok := cfg.(*connector.LocalConnectorConfig)
		if !ok {
			return errors.New("config for LocalConnector not a LocalConnectorConfig?")
		}

		if len(localCfg.PasswordInfos) > 0 {
			err := user.LoadPasswordInfos(s.PasswordInfoRepo,
				localCfg.PasswordInfos)
			if err != nil {
				return err
			}
		}
	}

	log.Infof("Loaded IdP connector: id=%s type=%s", connectorID, cfg.ConnectorType())
	return nil
}

func (s *Server) HTTPHandler() http.Handler {
	checks := make([]health.Checkable, len(s.HealthChecks))
	copy(checks, s.HealthChecks)
	for _, idpc := range s.Connectors {
		idpc := idpc
		checks = append(checks, idpc)
	}

	clock := clockwork.NewRealClock()
	mux := http.NewServeMux()
	mux.HandleFunc(httpPathDiscovery, handleDiscoveryFunc(s.ProviderConfig()))
	mux.HandleFunc(httpPathAuth, handleAuthFunc(s, s.Connectors, s.LoginTemplate))
	mux.HandleFunc(httpPathToken, handleTokenFunc(s))
	mux.HandleFunc(httpPathKeys, handleKeysFunc(s.KeyManager, clock))
	mux.HandleFunc(httpPathHealth, handleHealthFunc(checks))
	mux.HandleFunc(httpPathRegister, handleRegisterFunc(s))
	mux.HandleFunc(httpPathEmailVerify, handleEmailVerifyFunc(s.VerifyEmailTemplate,
		s.IssuerURL, s.KeyManager.PublicKeys, s.UserManager))
	pcfg := s.ProviderConfig()
	for _, idpc := range s.Connectors {
		errorURL, err := url.Parse(fmt.Sprintf("%s?connector_id=%s", pcfg.AuthEndpoint, idpc.ID()))
		if err != nil {
			log.Fatal(err)
		}
		idpc.Register(mux, *errorURL)
	}

	apiBasePath := path.Join(httpPathAPI, APIVersion)
	registerDiscoveryResource(apiBasePath, mux)

	clientPath, clientHandler := registerClientResource(apiBasePath, s.ClientIdentityRepo)
	ca := &clientTokenMiddleware{
		issuerURL: s.IssuerURL.String(),
		ciRepo:    s.ClientIdentityRepo,
		keysFunc:  s.KeyManager.PublicKeys,
		next:      clientHandler,
	}
	mux.Handle(path.Join(apiBasePath, clientPath), ca)

	return http.Handler(mux)
}

func (s *Server) ClientMetadata(clientID string) (*oidc.ClientMetadata, error) {
	return s.ClientIdentityRepo.Metadata(clientID)
}

func (s *Server) NewSession(ipdcID, clientID, clientState string, redirectURL url.URL, register bool) (string, error) {
	sessionID, err := s.SessionManager.NewSession(ipdcID, clientID, clientState, redirectURL, register)
	if err != nil {
		return "", err
	}

	log.Infof("Session %s created: clientID=%s clientState=%s", sessionID, clientID, clientState)
	return s.SessionManager.NewSessionKey(sessionID)
}

func (s *Server) Login(ident oidc.Identity, key string) (string, error) {
	sessionID, err := s.SessionManager.ExchangeKey(key)
	if err != nil {
		return "", err
	}

	ses, err := s.SessionManager.AttachRemoteIdentity(sessionID, ident)
	if err != nil {
		return "", err
	}
	log.Infof("Session %s remote identity attached: clientID=%s identity=%#v", sessionID, ses.ClientID, ident)

	if ses.Register {
		code, err := s.SessionManager.NewSessionKey(sessionID)
		if err != nil {
			return "", err
		}

		ru := s.absURL(httpPathRegister)
		q := ru.Query()
		q.Set("code", code)
		q.Set("state", ses.ClientState)
		ru.RawQuery = q.Encode()
		return ru.String(), nil
	}

	usr, err := s.UserRepo.GetByRemoteIdentity(user.RemoteIdentity{
		ConnectorID: ses.ConnectorID,
		ID:          ses.Identity.ID,
	})
	if err != nil {
		return "", err
	}

	ses, err = s.SessionManager.AttachUser(sessionID, usr.ID)
	if err != nil {
		return "", err
	}
	log.Infof("Session %s user identified: clientID=%s user=%#v", sessionID, ses.ClientID, usr)

	code, err := s.SessionManager.NewSessionKey(sessionID)
	if err != nil {
		return "", err
	}

	ru := ses.RedirectURL
	q := ru.Query()
	q.Set("code", code)
	q.Set("state", ses.ClientState)
	ru.RawQuery = q.Encode()

	return ru.String(), nil
}

func (s *Server) ClientCredsToken(creds oidc.ClientCredentials) (*jose.JWT, error) {
	ok, err := s.ClientIdentityRepo.Authenticate(creds)
	if err != nil {
		log.Errorf("Failed fetching client %s from repo: %v", creds.ID, err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	} else if !ok {
		return nil, oauth2.NewError(oauth2.ErrorInvalidClient)
	}

	signer, err := s.KeyManager.Signer()
	if err != nil {
		log.Errorf("Failed to generate ID token: %v", err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	}

	now := time.Now()
	exp := now.Add(s.SessionManager.ValidityWindow)
	claims := oidc.NewClaims(s.IssuerURL.String(), creds.ID, creds.ID, now, exp)
	claims.Add("name", creds.ID)

	jwt, err := jose.NewSignedJWT(claims, signer)
	if err != nil {
		log.Errorf("Failed to generate ID token: %v", err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	}

	log.Infof("Client token sent: clientID=%s", creds.ID)

	return jwt, nil
}

func (s *Server) CodeToken(creds oidc.ClientCredentials, sessionKey string) (*jose.JWT, error) {
	ok, err := s.ClientIdentityRepo.Authenticate(creds)
	if err != nil {
		log.Errorf("Failed fetching client %s from repo: %v", creds.ID, err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	} else if !ok {
		return nil, oauth2.NewError(oauth2.ErrorInvalidClient)
	}

	sessionID, err := s.SessionManager.ExchangeKey(sessionKey)
	if err != nil {
		return nil, oauth2.NewError(oauth2.ErrorInvalidGrant)
	}

	ses, err := s.SessionManager.Kill(sessionID)
	if err != nil {
		return nil, oauth2.NewError(oauth2.ErrorInvalidRequest)
	}

	if ses.ClientID != creds.ID {
		return nil, oauth2.NewError(oauth2.ErrorInvalidGrant)
	}

	signer, err := s.KeyManager.Signer()
	if err != nil {
		log.Errorf("Failed to generate ID token: %v", err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	}

	user, err := s.UserRepo.Get(ses.UserID)
	if err != nil {
		log.Errorf("Failed to fetch user %q from repo: %v: ", ses.UserID, err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	}

	claims := ses.Claims(s.IssuerURL.String())
	user.AddToClaims(claims)

	jwt, err := jose.NewSignedJWT(claims, signer)
	if err != nil {
		log.Errorf("Failed to generate ID token: %v", err)
		return nil, oauth2.NewError(oauth2.ErrorServerError)
	}

	log.Infof("Session %s token sent: clientID=%s", sessionID, creds.ID)

	return jwt, nil
}

type sortableIDPCs []connector.Connector

func (s sortableIDPCs) Len() int {
	return len([]connector.Connector(s))
}

func (s sortableIDPCs) Less(i, j int) bool {
	idpcs := []connector.Connector(s)
	return idpcs[i].ID() < idpcs[j].ID()
}

func (s sortableIDPCs) Swap(i, j int) {
	idpcs := []connector.Connector(s)
	idpcs[i], idpcs[j] = idpcs[j], idpcs[i]
}
