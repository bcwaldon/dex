package repo

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/user"
)

var makeTestUserRepo func() user.UserRepo

var (
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
		{
			User: user.User{
				ID:    "ID-2",
				Email: "Email-2@example.com",
			},
			RemoteIdentities: []user.RemoteIdentity{
				{
					ConnectorID: "IDPC-2",
					ID:          "RID-2",
				},
			},
		},
	}
)

func init() {
	dsn := os.Getenv("AUTHD_TEST_DSN")
	if dsn == "" {
		makeTestUserRepo = makeTestUserRepoMem
	} else {
		makeTestUserRepo = makeTestUserRepoDB(dsn)
	}
}

func makeTestUserRepoMem() user.UserRepo {
	return user.NewUserRepoFromUsers(testUsers)
}

func makeTestUserRepoDB(dsn string) func() user.UserRepo {
	return func() user.UserRepo {
		c := initDB(dsn)

		repo, err := db.NewUserRepoFromUsers(c, testUsers)
		if err != nil {
			panic(fmt.Sprintf("Unable to add users: %v", err))
		}
		return repo
	}

}

func TestNewUser(t *testing.T) {
	tests := []struct {
		user user.User
		err  error
	}{
		{
			user: user.User{
				Email: "bob@example.com",
			},
			err: nil,
		},
		{
			user: user.User{
				Email: "admin@example.com",
				Admin: true,
			},
			err: nil,
		},
		{
			user: user.User{
				Email:         "verified@example.com",
				EmailVerified: true,
			},
			err: nil,
		},
		{
			user: user.User{
				Email:       "Email-1@example.com",
				DisplayName: "Oops Same Email",
			},
			err: user.ErrorDuplicateEmail,
		},
		{
			user: user.User{
				ID:          "MyOwnID",
				Email:       "AnotherEmail@example.com",
				DisplayName: "Can't set your own ID!",
			},
			err: user.ErrorInvalidID,
		},
		{
			user: user.User{
				DisplayName: "No Email",
			},
			err: user.ErrorInvalidEmail,
		},
	}

	for i, tt := range tests {
		repo := makeTestUserRepo()
		id, err := repo.Create(tt.user)
		if tt.err != nil {
			if err != tt.err {
				t.Errorf("case %d: want=%v, got=%v", i, tt.err, err)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: want nil err, got %v", i, err)
			}

			gotUser, err := repo.Get(id)
			if err != nil {
				t.Errorf("case %d: want nil err, got %v", i, err)
			}

			tt.user.ID = id
			if diff := pretty.Compare(tt.user, gotUser); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i,
					diff)
			}
		}
	}
}

func TestUpdateUser(t *testing.T) {
	tests := []struct {
		user user.User
		err  error
	}{
		{
			// Update the email.
			user: user.User{
				ID:    "ID-1",
				Email: "Email-1.1@example.com",
			},
			err: nil,
		},
		{
			// No-op.
			user: user.User{
				ID:    "ID-1",
				Email: "Email-1@example.com",
			},
			err: nil,
		},
		{
			// No email.
			user: user.User{
				ID:    "ID-1",
				Email: "",
			},
			err: user.ErrorInvalidEmail,
		},
		{
			// Try Update on non-existent user.
			user: user.User{
				ID:    "NonExistent",
				Email: "GoodEmail@email.com",
			},
			err: user.ErrorNotFound,
		},
		{
			// Try update to someone else's email.
			user: user.User{
				ID:    "ID-2",
				Email: "Email-1@example.com",
			},
			err: user.ErrorDuplicateEmail,
		},
	}

	for i, tt := range tests {
		repo := makeTestUserRepo()
		err := repo.Update(tt.user)
		if tt.err != nil {
			if err != tt.err {
				t.Errorf("case %d: want=%q, got=%q", i, tt.err, err)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			gotUser, err := repo.Get(tt.user.ID)
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			if diff := pretty.Compare(tt.user, gotUser); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i,
					diff)
			}
		}
	}
}

func TestAttachRemoteIdentity(t *testing.T) {
	tests := []struct {
		id  string
		rid user.RemoteIdentity
		err error
	}{
		{
			id: "ID-1",
			rid: user.RemoteIdentity{
				ConnectorID: "IDPC-1",
				ID:          "RID-1.1",
			},
		},
		{
			id: "ID-1",
			rid: user.RemoteIdentity{
				ConnectorID: "IDPC-2",
				ID:          "RID-2",
			},
			err: user.ErrorDuplicateRemoteIdentity,
		},
		{
			id: "NoSuchUser",
			rid: user.RemoteIdentity{
				ConnectorID: "IDPC-3",
				ID:          "RID-3",
			},
			err: user.ErrorNotFound,
		},
	}

	for i, tt := range tests {
		repo := makeTestUserRepo()
		err := repo.AddRemoteIdentity(tt.id, tt.rid)
		if tt.err != nil {
			if err != tt.err {
				t.Errorf("case %d: want=%q, got=%q", i, tt.err, err)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			gotUser, err := repo.GetByRemoteIdentity(tt.rid)
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			wantUser, err := repo.Get(tt.id)
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			gotRIDs, err := repo.GetRemoteIdentities(tt.id)
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			if findRemoteIdentity(gotRIDs, tt.rid) == -1 {
				t.Errorf("case %d: user.RemoteIdentity not found", i)
			}

			if !reflect.DeepEqual(wantUser, gotUser) {
				t.Errorf("case %d: want=%#v, got=%#v", i,
					wantUser, gotUser)
			}
		}
	}
}

func TestRemoveRemoteIdentity(t *testing.T) {
	tests := []struct {
		id  string
		rid user.RemoteIdentity
		err error
	}{
		{
			id: "ID-1",
			rid: user.RemoteIdentity{
				ConnectorID: "IDPC-1",
				ID:          "RID-1",
			},
		},
		{
			id: "ID-1",
			rid: user.RemoteIdentity{
				ConnectorID: "IDPC-2",
				ID:          "RID-2",
			},
			err: user.ErrorNotFound,
		},
		{
			id: "NoSuchUser",
			rid: user.RemoteIdentity{
				ConnectorID: "IDPC-3",
				ID:          "RID-3",
			},
			err: user.ErrorNotFound,
		},
	}

	for i, tt := range tests {
		repo := makeTestUserRepo()
		err := repo.RemoveRemoteIdentity(tt.id, tt.rid)
		if tt.err != nil {
			if err != tt.err {
				t.Errorf("case %d: want=%q, got=%q", i, tt.err, err)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			gotUser, err := repo.GetByRemoteIdentity(tt.rid)
			if err == nil {
				if gotUser.ID == tt.id {
					t.Errorf("case %d: user found.", i)

				}
			} else if err != user.ErrorNotFound {
				t.Errorf("case %d: want %q err, got %q err", i, user.ErrorNotFound, err)
			}

			gotRIDs, err := repo.GetRemoteIdentities(tt.id)
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			if findRemoteIdentity(gotRIDs, tt.rid) != -1 {
				t.Errorf("case %d: user.RemoteIdentity found", i)
			}

		}
	}
}

func findRemoteIdentity(rids []user.RemoteIdentity, rid user.RemoteIdentity) int {
	for i, curRID := range rids {
		if curRID == rid {
			return i
		}
	}
	return -1
}

func TestNewUserRepoFromUsers(t *testing.T) {
	tests := []struct {
		users []user.UserWithRemoteIdentities
	}{
		{
			users: []user.UserWithRemoteIdentities{
				{
					User: user.User{
						ID:    "123",
						Email: "email123@example.com",
					},
					RemoteIdentities: []user.RemoteIdentity{},
				},
				{
					User: user.User{
						ID:    "456",
						Email: "email456@example.com",
					},
					RemoteIdentities: []user.RemoteIdentity{
						{
							ID:          "remoteID",
							ConnectorID: "connID",
						},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		repo := user.NewUserRepoFromUsers(tt.users)
		for _, want := range tt.users {
			gotUser, err := repo.Get(want.User.ID)
			if err != nil {
				t.Errorf("case %d: want nil err: %v", i, err)
			}

			gotRIDs, err := repo.GetRemoteIdentities(want.User.ID)
			if err != nil {
				t.Errorf("case %d: want nil err: %v", i, err)
			}

			if !reflect.DeepEqual(want.User, gotUser) {
				t.Errorf("case %d: want=%#v got=%#v", i, want.User, gotUser)
			}

			if !reflect.DeepEqual(want.RemoteIdentities, gotRIDs) {
				t.Errorf("case %d: want=%#v got=%#v", i, want.RemoteIdentities, gotRIDs)
			}
		}
	}
}

func TestGetByEmail(t *testing.T) {
	tests := []struct {
		email   string
		wantErr error
	}{
		{
			email:   "Email-1@example.com",
			wantErr: nil,
		},
		{
			email:   "NoSuchEmail@example.com",
			wantErr: user.ErrorNotFound,
		},
	}

	for i, tt := range tests {
		repo := makeTestUserRepo()
		gotUser, gotErr := repo.GetByEmail(tt.email)
		if tt.wantErr != nil {
			if tt.wantErr != gotErr {
				t.Errorf("case %d: wantErr=%q, gotErr=%q", i, tt.wantErr, gotErr)
			}
			continue
		}

		if gotErr != nil {
			t.Errorf("case %d: want nil err:% q", i, gotErr)
		}

		if tt.email != gotUser.Email {
			t.Errorf("case %d: want=%q, got=%q", i, tt.email, gotUser.Email)
		}
	}
}

func TestGetAdminCount(t *testing.T) {
	tests := []struct {
		addUsers []user.User
		want     int
	}{
		{
			addUsers: []user.User{
				user.User{
					Email: "Admin@example.com",
					Admin: true,
				},
			},
			want: 1,
		},
		{
			want: 0,
		},
		{
			addUsers: []user.User{
				user.User{
					Email: "NotAdmin@example.com",
				},
			},
			want: 0,
		},
		{
			addUsers: []user.User{
				user.User{
					Email: "Admin@example.com",
					Admin: true,
				},
				user.User{
					Email: "AnotherAdmin@example.com",
					Admin: true,
				},
			},
			want: 2,
		},
	}

	for i, tt := range tests {
		repo := makeTestUserRepo()
		for _, addUser := range tt.addUsers {
			_, err := repo.Create(addUser)
			if err != nil {
				t.Fatalf("case %d: couldn't add user: %q", i, err)
			}
		}

		got, err := repo.GetAdminCount()
		if err != nil {
			t.Errorf("case %d: couldn't get admin count: %q", i, err)
			continue
		}

		if tt.want != got {
			t.Errorf("case %d: want=%d, got=%d", i, tt.want, got)
		}
	}

}
