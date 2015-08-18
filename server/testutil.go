package server

import (
	"fmt"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"

	"github.com/coreos-inc/auth/client"
	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/email"
	"github.com/coreos-inc/auth/repo"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
	useremail "github.com/coreos-inc/auth/user/email"
)

const (
	templatesLocation      = "../static/html"
	emailTemplatesLocation = "../static/email"
)

var (
	testIssuerURL    = url.URL{Scheme: "http", Host: "server.example.com"}
	testClientID     = "XXX"
	testClientSecret = "secrete"

	testRedirectURL = url.URL{Scheme: "http", Host: "client.example.com", Path: "/callback"}

	testUsers = []user.UserWithRemoteIdentities{
		{
			User: user.User{
				ID:    "ID-1",
				Email: "Email-1@example.com",
			},
			RemoteIdentities: []user.RemoteIdentity{
				{
					ConnectorID: "IDPC-1",
					ID:          "RID-1",
				},
			},
		},
	}

	testPasswordInfos = []user.PasswordInfo{
		{
			UserID:   "ID-1",
			Password: []byte("password"),
		},
	}

	testPrivKey, _ = key.GeneratePrivateKey()
)

type testFixtures struct {
	srv                *Server
	userRepo           user.UserRepo
	sessionManager     *session.SessionManager
	emailer            *email.TemplatizedEmailer
	redirectURL        url.URL
	clientIdentityRepo client.ClientIdentityRepo
}

func sequentialGenerateCodeFunc() session.GenerateCodeFunc {
	x := 0
	return func() (string, error) {
		x += 1
		return fmt.Sprintf("code-%d", x), nil
	}
}

func makeTestFixtures() (*testFixtures, error) {
	userRepo := user.NewUserRepoFromUsers(testUsers)
	pwRepo := user.NewPasswordInfoRepoFromPasswordInfos(testPasswordInfos)
	manager := user.NewManager(userRepo, pwRepo, repo.InMemTransactionFactory, user.ManagerOptions{})

	connConfigs := []connector.ConnectorConfig{
		&connector.OIDCConnectorConfig{
			ID:           "oidc",
			IssuerURL:    testIssuerURL.String(),
			ClientID:     "12345",
			ClientSecret: "567789",
		},
		&connector.OIDCConnectorConfig{
			ID:                   "oidc-trusted",
			IssuerURL:            testIssuerURL.String(),
			ClientID:             "12345-trusted",
			ClientSecret:         "567789-trusted",
			TrustedEmailProvider: true,
		},
		&connector.LocalConnectorConfig{
			ID: "local",
		},
	}

	sessionManager := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	sessionManager.GenerateCode = sequentialGenerateCodeFunc()

	emailer, err := email.NewTemplatizedEmailerFromGlobs(
		emailTemplatesLocation+"/*.txt",
		emailTemplatesLocation+"/*.html",
		&email.FakeEmailer{})
	if err != nil {
		return nil, err
	}

	clientIdentityRepo := client.NewClientIdentityRepo([]oidc.ClientIdentity{
		oidc.ClientIdentity{
			Credentials: oidc.ClientCredentials{
				ID:     "XXX",
				Secret: testClientSecret,
			},
			Metadata: oidc.ClientMetadata{
				RedirectURLs: []url.URL{
					testRedirectURL,
				},
			},
		},
	})

	km := key.NewPrivateKeyManager()
	err = km.Set(key.NewPrivateKeySet([]*key.PrivateKey{testPrivKey}, time.Now().Add(time.Minute)))
	if err != nil {
		return nil, err
	}

	tpl, err := getTemplates(templatesLocation)
	if err != nil {
		return nil, err
	}

	srv := &Server{
		IssuerURL:          testIssuerURL,
		SessionManager:     sessionManager,
		ClientIdentityRepo: clientIdentityRepo,
		Templates:          tpl,
		UserRepo:           userRepo,
		PasswordInfoRepo:   pwRepo,
		UserManager:        manager,
		KeyManager:         km,
	}

	err = setTemplates(srv, tpl)
	if err != nil {
		return nil, err
	}

	for _, config := range connConfigs {
		if err := srv.AddConnector(config); err != nil {
			return nil, err
		}
	}

	srv.UserEmailer = useremail.NewUserEmailer(srv.UserRepo,
		srv.PasswordInfoRepo,
		srv.KeyManager.Signer,
		srv.SessionManager.ValidityWindow,
		srv.IssuerURL,
		emailer,
		"noreply@example.com",
		srv.absURL(httpPathResetPassword),
		srv.absURL(httpPathEmailVerify))

	return &testFixtures{
		srv:                srv,
		redirectURL:        testRedirectURL,
		userRepo:           userRepo,
		sessionManager:     sessionManager,
		emailer:            emailer,
		clientIdentityRepo: clientIdentityRepo,
	}, nil
}
