package server

import (
	"fmt"
	"net/url"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/email"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
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
)

type testFixtures struct {
	srv                *Server
	userRepo           user.UserRepo
	sessionManager     *session.SessionManager
	emailer            *email.TemplatizedEmailer
	redirectURL        url.URL
	clientIdentityRepo ClientIdentityRepo
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
	pwRepo := user.NewPasswordInfoRepo()
	manager := user.NewManager(userRepo, pwRepo, user.ManagerOptions{})

	tpl, err := getTemplates(templatesLocation)
	if err != nil {
		return nil, err
	}
	rtpl, err := findTemplate(RegisterTemplateName, tpl)
	if err != nil {
		return nil, err
	}

	connConfigs := []connector.ConnectorConfig{
		&connector.OIDCConnectorConfig{
			ID:           "oidc",
			IssuerURL:    testIssuerURL.String(),
			ClientID:     "12345",
			ClientSecret: "567789",
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
		email.FakeEmailer{})
	if err != nil {
		return nil, err
	}

	clientIdentityRepo := NewClientIdentityRepo([]oidc.ClientIdentity{
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

	srv := &Server{
		IssuerURL:          testIssuerURL,
		SessionManager:     sessionManager,
		ClientIdentityRepo: clientIdentityRepo,
		Templates:          tpl,
		UserRepo:           userRepo,
		PasswordInfoRepo:   pwRepo,
		UserManager:        manager,
		RegisterTemplate:   rtpl,
		Emailer:            emailer,
		KeyManager:         key.NewPrivateKeyManager(),
	}

	for _, config := range connConfigs {
		if err := srv.AddConnector(config); err != nil {
			return nil, err
		}
	}

	return &testFixtures{
		srv:                srv,
		redirectURL:        testRedirectURL,
		userRepo:           userRepo,
		sessionManager:     sessionManager,
		emailer:            emailer,
		clientIdentityRepo: clientIdentityRepo,
	}, nil
}
