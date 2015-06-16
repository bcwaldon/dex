package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/html"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
)

const (
	templatesLocation = "../static/html"
)

type testFixtures struct {
	srv            *Server
	userRepo       user.UserRepo
	sessionManager *session.SessionManager
	redirectURL    url.URL
}

func sequentialGenerateCodeFunc() session.GenerateCodeFunc {
	x := 0
	return func() (string, error) {
		x += 1
		return fmt.Sprintf("code-%d", x), nil
	}
}

func makeTestFixtures() (*testFixtures, error) {
	issuerURL := url.URL{Scheme: "http", Host: "server.example.com"}
	userRepo := user.NewUserRepo()
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

	redirectURL := url.URL{Scheme: "http", Host: "client.example.com", Path: "/callback"}

	connConfigs := []connector.ConnectorConfig{
		&connector.OIDCConnectorConfig{
			ID:           "oidc",
			IssuerURL:    issuerURL.String(),
			ClientID:     "12345",
			ClientSecret: "567789",
		},
		&connector.LocalConnectorConfig{
			ID: "local",
		},
	}

	sessionManager := session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo())
	sessionManager.GenerateCode = sequentialGenerateCodeFunc()
	srv := &Server{
		IssuerURL:      issuerURL,
		SessionManager: sessionManager,
		ClientIdentityRepo: NewClientIdentityRepo([]oidc.ClientIdentity{
			oidc.ClientIdentity{
				Credentials: oidc.ClientCredentials{
					ID:     "XXX",
					Secret: "secrete",
				},
				Metadata: oidc.ClientMetadata{
					RedirectURLs: []url.URL{
						redirectURL,
					},
				},
			},
		}),
		Templates:        tpl,
		UserRepo:         userRepo,
		PasswordInfoRepo: pwRepo,
		UserManager:      manager,
		RegisterTemplate: rtpl,
	}

	for _, config := range connConfigs {
		if err := srv.AddConnector(config); err != nil {
			return nil, err
		}
	}

	return &testFixtures{
		srv:            srv,
		redirectURL:    redirectURL,
		userRepo:       userRepo,
		sessionManager: sessionManager,
	}, nil
}

func TestHandleRegister(t *testing.T) {

	str := func(s string) []string {
		return []string{s}
	}
	tests := []struct {
		// inputs
		query        url.Values
		connID       string
		attachRemote bool

		// want
		wantStatus      int
		wantFormValues  url.Values
		wantUserCreated bool
	}{
		{
			// User comes in with a valid code, redirected from the connector,
			// and is shown the form.
			query: url.Values{
				"code": []string{"code-2"},
			},
			connID: "local",

			wantStatus: http.StatusOK,
			wantFormValues: url.Values{
				"code":     str("code-3"),
				"email":    str(""),
				"password": str(""),
				"validate": str("1"),
			},
		},
		{
			// User comes in with a valid code, having submitted the form, but
			// has a invalid email.
			query: url.Values{
				"code":     []string{"code-2"},
				"validate": []string{"1"},
				"email":    str(""),
				"password": str("password"),
			},
			connID:     "local",
			wantStatus: http.StatusBadRequest,
			wantFormValues: url.Values{
				"code":     str("code-3"),
				"email":    str(""),
				"password": str("password"),
				"validate": str("1"),
			},
		},
		{
			// User comes in with a valid code, having submitted the form. A new
			// user is created.
			query: url.Values{
				"code":     []string{"code-2"},
				"validate": []string{"1"},
				"email":    str("test@example.com"),
				"password": str("password"),
			},
			connID:          "local",
			wantStatus:      http.StatusSeeOther,
			wantUserCreated: true,
		},
		{
			// User comes in with a valid code, having submitted the form, but
			// there's no password.
			query: url.Values{
				"code":     []string{"code-2"},
				"validate": []string{"1"},
				"email":    str("test@example.com"),
			},
			connID:          "local",
			wantStatus:      http.StatusBadRequest,
			wantUserCreated: false,
			wantFormValues: url.Values{
				"code":     str("code-3"),
				"email":    str("test@example.com"),
				"password": str(""),
				"validate": str("1"),
			},
		},
		{
			// User comes in with a valid code, having submitted the form, but
			// there's no password, but they don't need one because connector ID
			// is oidc.
			query: url.Values{
				"code":     []string{"code-3"},
				"validate": []string{"1"},
				"email":    str("test@example.com"),
			},
			connID:          "oidc",
			attachRemote:    true,
			wantStatus:      http.StatusSeeOther,
			wantUserCreated: true,
		},
		{
			// Same as before, but missing a code.
			query: url.Values{
				"validate": []string{"1"},
				"email":    str("test@example.com"),
			},
			connID:          "oidc",
			attachRemote:    true,
			wantStatus:      http.StatusUnauthorized,
			wantUserCreated: false,
		},
	}

	for i, tt := range tests {
		f, err := makeTestFixtures()
		if err != nil {
			t.Fatalf("case %d: could not make test fixtures: %v", i, err)
		}

		key, err := f.srv.NewSession(tt.connID, "XXX", "", f.redirectURL, true)
		t.Logf("case %d: key for NewSession: %v", i, key)

		if tt.attachRemote {
			sesID, err := f.sessionManager.ExchangeKey(key)
			if err != nil {
				t.Fatalf("case %d: expected non-nil error: %v", i, err)
			}
			ses, err := f.sessionManager.Get(sesID)
			if err != nil {
				t.Fatalf("case %d: expected non-nil error: %v", i, err)
			}

			_, err = f.sessionManager.AttachRemoteIdentity(ses.ID, oidc.Identity{
				ID: "remoteID",
			})

			key, err := f.sessionManager.NewSessionKey(sesID)
			if err != nil {
				t.Fatalf("case %d: expected non-nil error: %v", i, err)
			}
			t.Logf("case %d: key for NewSession: %v", i, key)

		}

		hdlr := handleRegisterFunc(f.srv)

		w := httptest.NewRecorder()
		u := "http://server.example.com"
		req, err := http.NewRequest("POST", u, strings.NewReader(tt.query.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if err != nil {
			t.Errorf("case %d: unable to form HTTP request: %v", i, err)
		}

		hdlr.ServeHTTP(w, req)
		if tt.wantStatus != w.Code {
			t.Errorf("case %d: wantStatus=%v, got=%v", i, tt.wantStatus, w.Code)
		}

		email := tt.query.Get("email")
		if email != "" {
			_, err := f.userRepo.GetByEmail(email)
			if tt.wantUserCreated {
				if err != nil {
					t.Errorf("case %d: user not created: %v", i, err)
				}
			} else if err != user.ErrorNotFound {
				t.Errorf("case %d: unexpected error looking up user: want=%v, got=%v ", i, user.ErrorNotFound, err)
			}

		}

		values, err := html.FormValues("#registerForm", w.Body)
		if err != nil {
			t.Errorf("case %d: could not parse form: %v", i, err)
		}

		if diff := pretty.Compare(tt.wantFormValues, values); diff != "" {
			t.Errorf("case %d: Compare(want, got) = %v", i, diff)
		}

	}
}