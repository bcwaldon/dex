package user

import (
	"testing"

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
				ID:   "ID-1",
				Name: "Name-1",
			},
			RemoteIdentities: []RemoteIdentity{
				{
					ConnectorID: "local",
					ID:          "1",
				},
			},
		},
	})
	f.pwr = NewPasswordInfoRepo()
	f.mgr = NewManager(f.ur, f.pwr, ManagerOptions{})
	return f
}

func TestRegisterWithRemoteIdentity(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		emailVerified bool
		rid           RemoteIdentity
		err           error
	}{
		{
			name:          "name",
			email:         "email@example.com",
			emailVerified: false,
			rid: RemoteIdentity{
				ConnectorID: "local",
				ID:          "1234",
			},
			err: nil,
		},
		{
			email:         "email@example.com",
			emailVerified: false,
			rid: RemoteIdentity{
				ConnectorID: "local",
				ID:          "1234",
			},
			err: ErrorInvalidName,
		},
		{
			name:          "name",
			emailVerified: false,
			rid: RemoteIdentity{
				ConnectorID: "local",
				ID:          "1234",
			},
			err: ErrorInvalidEmail,
		},
		{
			name:          "name",
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
			tt.name,
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

		if usr.Name != tt.name {
			t.Errorf("case %d: user.Name: want=%q, got=%q", i, tt.name, usr.Name)
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
		name      string
		email     string
		plaintext string
		err       error
	}{
		{
			name:      "name",
			email:     "email@example.com",
			plaintext: "secretpassword123",
			err:       nil,
		},
		{
			email:     "email@example.com",
			plaintext: "secretpassword123",
			err:       ErrorInvalidName,
		},
		{
			name:      "name",
			plaintext: "secretpassword123",
			err:       ErrorInvalidEmail,
		},
		{
			name:  "name",
			email: "email@example.com",
			err:   ErrorInvalidPassword,
		},
	}

	for i, tt := range tests {
		f := makeTestFixtures()
		connID := "connID"
		userID, err := f.mgr.RegisterWithPassword(
			tt.name,
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

		if usr.Name != tt.name {
			t.Errorf("case %d: user.Name: want=%q, got=%q", i, tt.name, usr.Name)
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
