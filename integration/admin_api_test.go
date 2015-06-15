package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos-inc/auth/admin"
	"github.com/coreos-inc/auth/schema/adminschema"
	"github.com/coreos-inc/auth/server"
	"github.com/coreos-inc/auth/user"

	"github.com/coreos-inc/auth/Godeps/_workspace/src/google.golang.org/api/googleapi"
	"github.com/kylelemons/godebug/pretty"
)

type testFixtures struct {
	ur       user.UserRepo
	pwr      user.PasswordInfoRepo
	adAPI    *admin.AdminAPI
	adSrv    *server.AdminServer
	hSrv     *httptest.Server
	hc       *http.Client
	adClient *adminschema.Service
}

func (t *testFixtures) close() {
	t.hSrv.Close()
}

func makeTestFixtures() *testFixtures {
	f := &testFixtures{}

	f.ur = user.NewUserRepoFromUsers([]user.UserWithRemoteIdentities{
		{
			User: user.User{
				ID:    "ID-1",
				Email: "Email-1@example.com",
			},
		},
	})
	f.pwr = user.NewPasswordInfoRepoFromPasswordInfos([]user.PasswordInfo{
		{
			UserID:   "ID-1",
			Password: []byte("hi."),
		},
	})

	f.adAPI = admin.NewAdminAPI(f.ur, f.pwr, "local")
	f.adSrv = server.NewAdminServer(f.adAPI)
	f.hSrv = httptest.NewServer(f.adSrv.HTTPHandler())
	f.hc = &http.Client{}
	f.adClient, _ = adminschema.NewWithBasePath(f.hc, f.hSrv.URL)

	return f
}

func TestGetAdmin(t *testing.T) {

	tests := []struct {
		id      string
		errCode int
	}{
		{
			id:      "ID-1",
			errCode: -1,
		},
		{
			id:      "ID-2",
			errCode: http.StatusNotFound,
		},
	}

	for i, tt := range tests {
		func() {
			f := makeTestFixtures()
			defer f.close()
			admn, err := f.adClient.Admin.Get(tt.id).Do()
			if tt.errCode != -1 {
				if err == nil {
					t.Errorf("case %d: err was nil", i)
					return
				}
				gErr, ok := err.(*googleapi.Error)
				if !ok {
					t.Errorf("case %d: not a googleapi Error: %q", i, err)
					return
				}

				if gErr.Code != tt.errCode {
					t.Errorf("case %d: want=%d, got=%d", i, tt.errCode, gErr.Code)
					return
				}
			} else {
				if err != nil {
					t.Errorf("case %d: err != nil: %q", i, err)
				}
				if admn == nil {
					t.Errorf("case %d: admn was nil", i)
				}

				if admn.Id != "ID-1" {
					t.Errorf("case %d: want=%q, got=%q", i, tt.id, admn.Id)
				}
			}
		}()
	}
}

func TestCreateAdmin(t *testing.T) {
	tests := []struct {
		admn    *adminschema.Admin
		errCode int
	}{
		{
			admn: &adminschema.Admin{
				Email:    "foo@example.com",
				Password: "foopass",
			},
			errCode: -1,
		},
		{
			// duplicate Email
			admn: &adminschema.Admin{
				Email:    "Email-1@example.com",
				Password: "foopass",
			},
			errCode: http.StatusBadRequest,
		},
		{
			// missing Email
			admn: &adminschema.Admin{
				Password: "foopass",
			},
			errCode: http.StatusBadRequest,
		},
	}
	for i, tt := range tests {
		func() {
			f := makeTestFixtures()
			defer f.close()

			admn, err := f.adClient.Admin.Create(tt.admn).Do()
			if tt.errCode != -1 {
				if err == nil {
					t.Errorf("case %d: err was nil", i)
					return
				}
				gErr, ok := err.(*googleapi.Error)
				if !ok {
					t.Errorf("case %d: not a googleapi Error: %q", i, err)
					return
				}

				if gErr.Code != tt.errCode {
					t.Errorf("case %d: want=%d, got=%d", i, tt.errCode, gErr.Code)
					return
				}
			} else {
				if err != nil {
					t.Errorf("case %d: err != nil: %q", i, err)
				}

				tt.admn.Id = admn.Id
				if diff := pretty.Compare(tt.admn, admn); diff != "" {
					t.Errorf("case %d: Compare(want, got) = %v", i, diff)
				}

				gotAdmn, err := f.adClient.Admin.Get(admn.Id).Do()
				if err != nil {
					t.Errorf("case %d: err != nil: %q", i, err)
				}
				if diff := pretty.Compare(admn, gotAdmn); diff != "" {
					t.Errorf("case %d: Compare(want, got) = %v", i, diff)
				}

				usr, err := f.ur.GetByRemoteIdentity(user.RemoteIdentity{
					ConnectorID: "local",
					ID:          tt.admn.Id,
				})
				if err != nil {
					t.Errorf("case %d: err != nil: %q", i, err)
				}

				if usr.ID != tt.admn.Id {
					t.Errorf("case %d: want=%q, got=%q", i, tt.admn.Id, usr.ID)
				}

			}
		}()
	}
}

func TestGetState(t *testing.T) {
	tests := []struct {
		addUsers []user.User
		want     adminschema.State
	}{
		{
			addUsers: []user.User{
				user.User{
					Email: "Admin@example.com",
					Admin: true,
				},
			},
			want: adminschema.State{
				AdminUserCreated: true,
			},
		},
		{
			want: adminschema.State{
				AdminUserCreated: false,
			},
		},
	}

	for i, tt := range tests {
		func() {
			f := makeTestFixtures()
			defer f.close()

			for _, usr := range tt.addUsers {
				_, err := f.ur.Create(usr)
				if err != nil {
					t.Fatalf("case %d: err != nil: %v", i, err)
				}
			}

			got, err := f.adClient.State.Get().Do()
			if err != nil {
				t.Errorf("case %d: err != nil: %q", i, err)
			}

			if diff := pretty.Compare(tt.want, got); diff != "" {
				t.Errorf("case %d: Compare(want, got) = %v", i, diff)
			}

		}()
	}

}
