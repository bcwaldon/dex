package server

import (
	"net/url"
	"reflect"
	"sort"
	"testing"

	"github.com/coreos-inc/auth/oidc"
)

func TestMemClientIdentityRepoNew(t *testing.T) {
	tests := []struct {
		meta oidc.ClientMetadata
	}{
		{
			meta: oidc.ClientMetadata{
				RedirectURLs: []url.URL{
					url.URL{
						Scheme: "https",
						Host:   "example.com",
					},
				},
			},
		},
		{
			meta: oidc.ClientMetadata{
				RedirectURLs: []url.URL{
					url.URL{
						Scheme: "https",
						Host:   "example.com/foo",
					},
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

		wantURLs := tt.meta.RedirectURLs
		gotURLs := all[0].Metadata.RedirectURLs
		if !reflect.DeepEqual(wantURLs, gotURLs) {
			t.Errorf("case %d: redirect url mismatch, want=%v, got=%v", i, wantURLs, gotURLs)
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
