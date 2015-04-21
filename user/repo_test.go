package user

import (
	"reflect"
	"testing"
)

func makeTestUserRepo() UserRepo {
	users := []totalUser{
		{
			User: User{
				ID:   "ID-1",
				Name: "Name-1",
			},
			RemoteIdentities: []RemoteIdentity{
				{
					ConnectorID: "IDPC-1",
					ID:          "RID-1",
				},
			},
		},
		{
			User: User{
				ID:   "ID-2",
				Name: "Name-2",
			},
			RemoteIdentities: []RemoteIdentity{
				{
					ConnectorID: "IDPC-2",
					ID:          "RID-2",
				},
			},
		},
	}

	return newUserRepoFromUsers(users)
}

func TestNewUser(t *testing.T) {
	tests := []struct {
		user User
		err  error
	}{
		{
			user: User{
				Name: "AnotherName",
			},
			err: nil,
		},
		{
			user: User{
				Name:        "Name-1",
				DisplayName: "Oops Same Name",
			},
			err: ErrorDuplicateName,
		},
		{
			user: User{
				ID:          "MyOwnID",
				Name:        "AnotherName",
				DisplayName: "Can't set your own ID!",
			},
			err: ErrorInvalidID,
		},
		{
			user: User{
				DisplayName: "No Name",
			},
			err: ErrorInvalidName,
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
			if !reflect.DeepEqual(tt.user, gotUser) {
				t.Errorf("case %d: want=%#v, got=%#v", i,
					tt.user, gotUser)
			}
		}
	}
}

func TestUpdate(t *testing.T) {
	tests := []struct {
		user User
		err  error
	}{
		{
			// Update the name.
			user: User{
				ID:   "ID-1",
				Name: "Name-1.1",
			},
			err: nil,
		},
		{
			// No-op.
			user: User{
				ID:   "ID-1",
				Name: "Name-1",
			},
			err: nil,
		},
		{
			// No name.
			user: User{
				ID:   "ID-1",
				Name: "",
			},
			err: ErrorInvalidName,
		},
		{
			// Try Update on non-existent user.
			user: User{
				ID:   "NonExistent",
				Name: "GoodName",
			},
			err: ErrorNotFound,
		},
		{
			// Try update to someone else's name.
			user: User{
				ID:   "ID-2",
				Name: "Name-1",
			},
			err: ErrorDuplicateName,
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

			if !reflect.DeepEqual(tt.user, gotUser) {
				t.Errorf("case %d: want=%#v, got=%#v", i,
					tt.user, gotUser)
			}
		}
	}
}

func TestAttachRemoteIdentity(t *testing.T) {
	tests := []struct {
		id  string
		rid RemoteIdentity
		err error
	}{
		{
			id: "ID-1",
			rid: RemoteIdentity{
				ConnectorID: "IDPC-1",
				ID:          "RID-1.1",
			},
		},
		{
			id: "ID-1",
			rid: RemoteIdentity{
				ConnectorID: "IDPC-2",
				ID:          "RID-2",
			},
			err: ErrorDuplicateRemoteIdentity,
		},
		{
			id: "NoSuchUser",
			rid: RemoteIdentity{
				ConnectorID: "IDPC-3",
				ID:          "RID-3",
			},
			err: ErrorNotFound,
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
				t.Errorf("case %d: RemoteIdentity not found", i)
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
		rid RemoteIdentity
		err error
	}{
		{
			id: "ID-1",
			rid: RemoteIdentity{
				ConnectorID: "IDPC-1",
				ID:          "RID-1",
			},
		},
		{
			id: "ID-1",
			rid: RemoteIdentity{
				ConnectorID: "IDPC-2",
				ID:          "RID-2",
			},
			err: ErrorNotFound,
		},
		{
			id: "NoSuchUser",
			rid: RemoteIdentity{
				ConnectorID: "IDPC-3",
				ID:          "RID-3",
			},
			err: ErrorNotFound,
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
			} else if err != ErrorNotFound {
				t.Errorf("case %d: want %q err, got %q err", i, ErrorNotFound, err)
			}

			gotRIDs, err := repo.GetRemoteIdentities(tt.id)
			if err != nil {
				t.Errorf("case %d: want nil err, got %q", i, err)
			}

			if findRemoteIdentity(gotRIDs, tt.rid) != -1 {
				t.Errorf("case %d: RemoteIdentity found", i)
			}

		}
	}
}

func findRemoteIdentity(rids []RemoteIdentity, rid RemoteIdentity) int {
	for i, curRID := range rids {
		if curRID == rid {
			return i
		}
	}
	return -1
}

func TestNewUserRepoFromUsers(t *testing.T) {
	tests := []struct {
		users []totalUser
	}{
		{
			users: []totalUser{
				{
					User: User{
						ID:   "123",
						Name: "name123",
					},
					RemoteIdentities: []RemoteIdentity{},
				},
				{
					User: User{
						ID:   "456",
						Name: "name456",
					},
					RemoteIdentities: []RemoteIdentity{
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
		repo := newUserRepoFromUsers(tt.users)
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
