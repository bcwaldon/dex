package user

import (
	"net/url"
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/kylelemons/godebug/pretty"
)

type testFixtures struct {
	ur  UserRepo
	pwr PasswordInfoRepo
	mgr *Manager
}

func makeTestFixtures() *testFixtures {
	f := &testFixtures{}

	f.ur = NewUserRepoFromUsers([]UserWithRemoteIdentities{
		{
			User: User{
				ID:    "ID-1",
				Email: "Email-1@example.com",
			},
			RemoteIdentities: []RemoteIdentity{
				{
					ConnectorID: "local",
					ID:          "1",
				},
			},
		}, {
			User: User{
				ID:            "ID-2",
				Email:         "Email-2@example.com",
				EmailVerified: true,
			},
			RemoteIdentities: []RemoteIdentity{
				{
					ConnectorID: "local",
					ID:          "2",
				},
			},
		},
	})
	f.pwr = NewPasswordInfoRepoFromPasswordInfos([]PasswordInfo{
		{
			UserID:   "ID-1",
			Password: []byte("password-1"),
		},
		{
			UserID:   "ID-2",
			Password: []byte("password-2"),
		},
	})
	f.mgr = NewManager(f.ur, f.pwr, ManagerOptions{})
	return f
}

func TestRegisterWithRemoteIdentity(t *testing.T) {
	tests := []struct {
		email         string
		emailVerified bool
		rid           RemoteIdentity
		err           error
	}{
		{
			email:         "email@example.com",
			emailVerified: false,
			rid: RemoteIdentity{
				ConnectorID: "local",
				ID:          "1234",
			},
			err: nil,
		},
		{
			emailVerified: false,
			rid: RemoteIdentity{
				ConnectorID: "local",
				ID:          "1234",
			},
			err: ErrorInvalidEmail,
		},
		{
			email:         "email@example.com",
			emailVerified: false,
			rid: RemoteIdentity{
				ConnectorID: "local",
				ID:          "1",
			},
			err: ErrorDuplicateRemoteIdentity,
		},
	}

	for i, tt := range tests {
		f := makeTestFixtures()
		userID, err := f.mgr.RegisterWithRemoteIdentity(
			tt.email,
			tt.emailVerified,
			tt.rid)

		if tt.err != nil {
			if tt.err != err {
				t.Errorf("case %d: want=%q, got=%q", i, tt.err, err)
			}
			continue
		}

		usr, err := f.ur.Get(userID)
		if err != nil {
			t.Errorf("case %d: err != nil: %q", i, err)
		}

		if usr.Email != tt.email {
			t.Errorf("case %d: user.Email: want=%q, got=%q", i, tt.email, usr.Email)
		}
		if usr.EmailVerified != tt.emailVerified {
			t.Errorf("case %d: user.EmailVerified: want=%v, got=%v", i, tt.emailVerified, usr.EmailVerified)
		}

		ridUSR, err := f.ur.GetByRemoteIdentity(tt.rid)
		if err != nil {
			t.Errorf("case %d: err != nil: %q", i, err)
		}
		if diff := pretty.Compare(usr, ridUSR); diff != "" {
			t.Errorf("case %d: Compare(want, got) = %v", i, diff)
		}
	}
}

func TestRegisterWithPassword(t *testing.T) {
	tests := []struct {
		email     string
		plaintext string
		err       error
	}{
		{
			email:     "email@example.com",
			plaintext: "secretpassword123",
			err:       nil,
		},
		{
			plaintext: "secretpassword123",
			err:       ErrorInvalidEmail,
		},
		{
			email: "email@example.com",
			err:   ErrorInvalidPassword,
		},
	}

	for i, tt := range tests {
		f := makeTestFixtures()
		connID := "connID"
		userID, err := f.mgr.RegisterWithPassword(
			tt.email,
			tt.plaintext,
			connID)

		if tt.err != nil {
			if tt.err != err {
				t.Errorf("case %d: want=%q, got=%q", i, tt.err, err)
			}
			continue
		}

		usr, err := f.ur.Get(userID)
		if err != nil {
			t.Errorf("case %d: err != nil: %q", i, err)
		}

		if usr.Email != tt.email {
			t.Errorf("case %d: user.Email: want=%q, got=%q", i, tt.email, usr.Email)
		}
		if usr.EmailVerified != false {
			t.Errorf("case %d: user.EmailVerified: want=%v, got=%v", i, false, usr.EmailVerified)
		}

		ridUSR, err := f.ur.GetByRemoteIdentity(RemoteIdentity{
			ID:          userID,
			ConnectorID: connID,
		})
		if err != nil {
			t.Errorf("case %d: err != nil: %q", i, err)
		}
		if diff := pretty.Compare(usr, ridUSR); diff != "" {
			t.Errorf("case %d: Compare(want, got) = %v", i, diff)
		}

		pwi, err := f.pwr.Get(userID)
		if err != nil {
			t.Errorf("case %d: err != nil: %q", i, err)
		}
		ident, err := pwi.Authenticate(tt.plaintext)
		if err != nil {
			t.Errorf("case %d: err != nil: %q", i, err)
		}
		if ident.ID != userID {
			t.Errorf("case %d: ident.ID: want=%q, got=%q", i, userID, ident.ID)
		}

		_, err = pwi.Authenticate(tt.plaintext + "WRONG")
		if err == nil {
			t.Errorf("case %d: want non-nil err", i)
		}
	}
}

func TestVerifyEmail(t *testing.T) {
	now := time.Now()
	issuer, _ := url.Parse("http://example.com")
	clientID := "myclient"
	callback := "http://client.example.com/callback"
	expires := time.Hour * 3

	makeClaims := func(usr User) jose.Claims {
		return map[string]interface{}{
			"iss": issuer.String(),
			"aud": clientID,
			ClaimEmailVerificationCallback: callback,
			ClaimEmailVerificationEmail:    usr.Email,
			"exp": float64(now.Add(expires).Unix()),
			"sub": usr.ID,
			"iat": float64(now.Unix()),
		}
	}

	tests := []struct {
		evClaims jose.Claims
		wantErr  bool
	}{
		{
			// happy path
			evClaims: makeClaims(User{ID: "ID-1", Email: "Email-1@example.com"}),
		},
		{
			// non-matching email
			evClaims: makeClaims(User{ID: "ID-1", Email: "Email-2@example.com"}),
			wantErr:  true,
		},
		{
			// already verified email
			evClaims: makeClaims(User{ID: "ID-2", Email: "Email-2@example.com"}),
			wantErr:  true,
		},
		{
			// non-existent user.
			evClaims: makeClaims(User{ID: "ID-UNKNOWN", Email: "noone@example.com"}),
			wantErr:  true,
		},
	}

	for i, tt := range tests {
		f := makeTestFixtures()
		cb, err := f.mgr.VerifyEmail(EmailVerification{tt.evClaims})
		if tt.wantErr {
			if err == nil {
				t.Errorf("case %d: want non-nil err", i)
			}
			continue
		}

		if err != nil {
			t.Errorf("case %d: want err=nil got=%q", i, err)
		}

		if cb.String() != tt.evClaims[ClaimEmailVerificationCallback] {
			t.Errorf("case %d: want=%q, got=%q", i, cb.String(),
				tt.evClaims[ClaimEmailVerificationCallback])
		}
	}
}

func TestChangePassword(t *testing.T) {
	now := time.Now()
	issuer, _ := url.Parse("http://example.com")
	clientID := "myclient"
	callback := "http://client.example.com/callback"
	expires := time.Hour * 3
	password := "password-1"

	makeClaims := func(usrID, callback string) jose.Claims {
		return map[string]interface{}{
			"iss": issuer.String(),
			"aud": clientID,
			ClaimPasswordResetCallback: callback,
			ClaimPasswordResetPassword: password,
			"exp": float64(now.Add(expires).Unix()),
			"sub": usrID,
			"iat": float64(now.Unix()),
		}
	}

	tests := []struct {
		pwrClaims   jose.Claims
		newPassword string
		wantErr     bool
	}{
		{
			// happy path
			pwrClaims:   makeClaims("ID-1", callback),
			newPassword: "password-1.1",
		},
		{
			// happy path with no callback
			pwrClaims:   makeClaims("ID-1", ""),
			newPassword: "password-1.1",
		},
		{
			// passwords don't match changed
			pwrClaims:   makeClaims("ID-2", callback),
			newPassword: "password-1.1",
			wantErr:     true,
		},
		{
			// user doesn't exist
			pwrClaims:   makeClaims("ID-123", callback),
			newPassword: "password-1.1",
			wantErr:     true,
		},
	}

	for i, tt := range tests {
		f := makeTestFixtures()
		cb, err := f.mgr.ChangePassword(PasswordReset{tt.pwrClaims}, tt.newPassword)
		if tt.wantErr {
			if err == nil {
				t.Errorf("case %d: want non-nil err", i)
			}
			continue
		}

		if err != nil {
			t.Errorf("case %d: want err=nil got=%q", i, err)
			continue
		}

		var cbString string
		if cb != nil {
			cbString = cb.String()
		}
		if cbString != tt.pwrClaims[ClaimPasswordResetCallback] {
			t.Errorf("case %d: want=%q, got=%q", i, cb.String(),
				tt.pwrClaims[ClaimPasswordResetCallback])
		}
	}
}
