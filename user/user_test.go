package user

import (
	"reflect"
	"strings"
	"testing"
)

func TestNewUsersFromReader(t *testing.T) {
	tests := []struct {
		json string
		want []User
	}{
		{
			json: `[{"id":"12345","name":"elroy", "displayName": "Elroy Canis", "remoteIdentities":[{"idpID":"google", "id":"elroy@example.com"}] }]`,
			want: []User{
				{
					ID:          "12345",
					Name:        "elroy",
					DisplayName: "Elroy Canis",
					RemoteIdentities: []RemoteIdentity{
						{
							IDPCID: "google",
							ID:     "elroy@example.com",
						},
					},
				},
			},
		},
	}

	for i, tt := range tests {
		r := strings.NewReader(tt.json)
		us, err := newUsersFromReader(r)
		if err != nil {
			t.Errorf("case %d: want nil err: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(us, tt.want) {
			t.Errorf("case %d: want=%#v got=%#v", i, tt.want, us)
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
