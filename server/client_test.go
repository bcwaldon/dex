package server

import (
	"net/url"
	"reflect"
	"sort"
	"testing"

	"github.com/coreos-inc/auth/oidc"
)

type sortableClientIdentities []oidc.ClientIdentity

func (s sortableClientIdentities) Len() int {
	return len([]oidc.ClientIdentity(s))
}

func (s sortableClientIdentities) Less(i, j int) bool {
	cs := []oidc.ClientIdentity(s)
	return cs[i].Credentials.ID < cs[j].Credentials.ID
}

func (s sortableClientIdentities) Swap(i, j int) {
	cs := []oidc.ClientIdentity(s)
	cs[i], cs[j] = cs[j], cs[i]
}

func TestMemClientIdentityRepoNew(t *testing.T) {
	tests := []struct {
		meta oidc.ClientMetadata
	}{
		{
			meta: oidc.ClientMetadata{
				RedirectURL: url.URL{
					Scheme: "https",
					Host:   "example.com",
				},
			},
		},
		{
			meta: oidc.ClientMetadata{
				RedirectURL: url.URL{
					Scheme: "https",
					Host:   "example.com/foo",
				},
			},
		},
	}

	for i, tt := range tests {
		cr := NewClientIdentityRepo(nil)
		creds, err := cr.New(tt.meta)
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
		}

		if creds.ID == "" {
			t.Errorf("case %d: expected non-empty Client ID", i)
		}

		if creds.Secret == "" {
			t.Errorf("case %d: expected non-empty Client Secret", i)
		}

		all, err := cr.All()
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
		}
		if len(all) != 1 {
			t.Errorf("case %d: expected repo to contain newly created Client", i)
		}

		uWant := tt.meta.RedirectURL
		uGot := all[0].Metadata.RedirectURL
		if uWant != uGot {
			t.Errorf("case %d: redirect url mismatch, want=%v, got=%v", i, uWant, uGot)
		}
	}
}

func TestMemClientIdentityRepoAll(t *testing.T) {
	tests := []struct {
		ids []string
	}{
		{
			ids: nil,
		},
		{
			ids: []string{"foo"},
		},
		{
			ids: []string{"foo", "bar"},
		},
	}

	for i, tt := range tests {
		cs := make([]oidc.ClientIdentity, len(tt.ids))
		for i, s := range tt.ids {
			cs[i] = oidc.ClientIdentity{
				Credentials: oidc.ClientCredentials{
					ID: s,
				},
			}
		}

		cr := NewClientIdentityRepo(cs)

		all, err := cr.All()
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
		}

		want := sortableClientIdentities(cs)
		sort.Sort(want)
		got := sortableClientIdentities(all)
		sort.Sort(got)

		if len(got) != len(want) {
			t.Errorf("case %d: wrong length: %d", i, len(got))
		}

		if !reflect.DeepEqual(want, got) {
			t.Errorf("case %d: want=%#v, got=%#v", i, want, got)
		}
	}
}
