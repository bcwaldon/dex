package user

import (
	"reflect"
	"testing"
)

func TestSet(t *testing.T) {
	makeRepo := func() (UserRepo, error) {
		repo := NewUserRepo()
		for _, user := range []User{
			{
				ID:   "ID-1",
				Name: "Name-1",
				RemoteIdentities: []RemoteIdentity{
					{
						ConnectorID: "IDPC-1",
						ID:          "RID-1",
					},
				},
			},
		} {
			err := repo.Set(user)
			if err != nil {
				return nil, err
			}
		}
		return repo, nil
	}

	tests := []struct {
		user User
		err  error
	}{
		{
			user: User{
				// Brand New User
				ID:   "NEW_ID",
				Name: "New Name",
				RemoteIdentities: []RemoteIdentity{
					{
						ConnectorID: "IDPC-1",
						ID:          "RID-2",
					},
				},
			},
			err: nil,
		},
		{
			user: User{
				// Old User, new Name
				ID:   "ID-1",
				Name: "New Name",
				RemoteIdentities: []RemoteIdentity{
					{
						ConnectorID: "IDPC-1",
						ID:          "RID-1",
					},
				},
			},
			err: nil,
		},
		{
			user: User{
				// No Name
				ID: "NO-NAME",
				RemoteIdentities: []RemoteIdentity{
					{
						ConnectorID: "IDPC-1",
						ID:          "RID-NONAME",
					},
				},
			},
			err: ErrorInvalidName,
		},
		{
			user: User{
				// No ID
				Name: "NO-ID",
				RemoteIdentities: []RemoteIdentity{
					{
						ConnectorID: "IDPC-1",
						ID:          "RID-NONAME",
					},
				},
			},
			err: ErrorInvalidID,
		},
		{
			user: User{
				// Duplicate Name
				ID:   "DUP-ID",
				Name: "Name-1",
				RemoteIdentities: []RemoteIdentity{
					{
						ConnectorID: "IDPC-1",
						ID:          "RID-DUP-ID",
					},
				},
			},
			err: ErrorDuplicateName,
		},
		{
			user: User{
				// Duplicate Remote Identity
				ID:   "DUPE-RI",
				Name: "DUPE-RI-NAME",
				RemoteIdentities: []RemoteIdentity{
					{
						ConnectorID: "IDPC-1",
						ID:          "RID-1",
					},
				},
			},
			err: ErrorDuplicateRemoteIdentity,
		},
	}

	for i, tt := range tests {
		repo, err := makeRepo()
		if err != nil {
			t.Errorf("case %d: could not make UserRepo: %v", i, err)
		}

		err = repo.Set(tt.user)
		if err != tt.err {
			t.Errorf("case %d: want=%v, got=%v", i, tt.err, err)
		}

		var notSet = tt.err != nil
		user, err := repo.Get(tt.user.ID)

		if notSet {
			if err != ErrorNotFound {
				t.Errorf("case %d: want=%v, got=%v", i, ErrorNotFound, err)
			}
			if user.ID != "" {
				t.Errorf("case %d: want=%q, got=%q", i, "", user.ID)
			}
		} else {
			if err != nil {
				t.Errorf("case %d: want=%v, got=%v", i, nil, err)
			}
			if user.ID != tt.user.ID {
				t.Errorf("case %d: want=%q, got=%q", i, user.ID, tt.user.ID)
			}
		}

		for ridx, ri := range tt.user.RemoteIdentities {
			user, err := repo.GetByRemoteIdentity(ri)
			if notSet {
				if user.ID == tt.user.ID && tt.user.ID != "" {
					t.Errorf("case %d: remoteID: %d: user.ID == tt.user.ID", i,
						ridx)
				}
			} else {
				if err != nil {
					t.Errorf("case %d: remoteID: %d: want=%v, got=%v", i,
						ridx, nil, err)
				}
				if user.ID != tt.user.ID {
					t.Errorf("case %d: remoteID: %d: want=%q, got=%q", i,
						ridx, tt.user.ID, user.ID)
				}
			}
		}
	}
}

func TestNewUserRepoFromUsers(t *testing.T) {
	tests := []struct {
		users []User
	}{
		{
			users: []User{
				{
					ID:   "123",
					Name: "name123",
				},
				{
					ID:   "456",
					Name: "name456",
				},
			},
		},
	}

	for i, tt := range tests {
		repo := newUserRepoFromUsers(tt.users)
		for _, want := range tt.users {
			got, err := repo.Get(want.ID)
			if err != nil {
				t.Errorf("case %d: want nil err: %v", i, err)
			}

			if !reflect.DeepEqual(want, got) {
				t.Errorf("case %d: want=%#v got=%#v", i, want, got)
			}
		}
	}
}
