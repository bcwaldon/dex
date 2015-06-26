package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/html"
	"github.com/coreos-inc/auth/user"
)

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
