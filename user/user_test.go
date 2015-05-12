package user

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/coreos-inc/auth/jose"
)

func TestNewUsersFromReader(t *testing.T) {
	tests := []struct {
		json string
		want []UserWithRemoteIdentities
	}{
		{
			json: `[{"user":{"id":"12345","name":"elroy", "displayName": "Elroy Canis", "email":"elroy23@example.com"}, "remoteIdentities":[{"connectorID":"google", "id":"elroy@example.com"}] }]`,
			want: []UserWithRemoteIdentities{
				{
					User: User{
						ID:          "12345",
						Name:        "elroy",
						DisplayName: "Elroy Canis",
						Email:       "elroy23@example.com",
					},
					RemoteIdentities: []RemoteIdentity{
						{
							ConnectorID: "google",
							ID:          "elroy@example.com",
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
		if diff := pretty.Compare(tt.want, us); diff != "" {
			t.Errorf("case %d: Compare(want, got): %v", i, diff)
		}
	}
}

func TestAddToClaims(t *testing.T) {
	tests := []struct {
		user         User
		wantedClaims jose.Claims
	}{
		{
			user: User{
				Name:        "testUserName",
				DisplayName: "Test User Name",
			},
			wantedClaims: jose.Claims{
				"name":               "Test User Name",
				"preferred_username": "testUserName",
			},
		},
	}

	for i, tt := range tests {
		claims := jose.Claims{}
		tt.user.AddToClaims(claims)
		if !reflect.DeepEqual(claims, tt.wantedClaims) {
			t.Errorf("case %d: want=%#v, got=%#v", i, claims, tt.wantedClaims)
		}
	}
}
