package oauth2

import (
	"net/url"
	"reflect"
	"testing"
)

func TestParseAuthCodeRequest(t *testing.T) {
	tests := []struct {
		query   url.Values
		wantACR AuthCodeRequest
		wantErr error
	}{
		// no redirect_uri
		{
			query: url.Values{
				"response_type": []string{"code"},
				"scope":         []string{"foo bar baz"},
				"client_id":     []string{"XXX"},
				"state":         []string{"pants"},
			},
			wantACR: AuthCodeRequest{
				ResponseType: "code",
				ClientID:     "XXX",
				Scope:        []string{"foo", "bar", "baz"},
				State:        "pants",
				RedirectURL:  nil,
			},
		},

		// with redirect_uri
		{
			query: url.Values{
				"response_type": []string{"code"},
				"redirect_uri":  []string{"https://127.0.0.1:5555/callback?foo=bar"},
				"scope":         []string{"foo bar baz"},
				"client_id":     []string{"XXX"},
				"state":         []string{"pants"},
			},
			wantACR: AuthCodeRequest{
				ResponseType: "code",
				ClientID:     "XXX",
				Scope:        []string{"foo", "bar", "baz"},
				State:        "pants",
				RedirectURL: &url.URL{
					Scheme:   "https",
					Host:     "127.0.0.1:5555",
					Path:     "/callback",
					RawQuery: "foo=bar",
				},
			},
		},

		// unsupported response_type doesn't trigger error
		{
			query: url.Values{
				"response_type": []string{"token"},
				"redirect_uri":  []string{"https://127.0.0.1:5555/callback?foo=bar"},
				"scope":         []string{"foo bar baz"},
				"client_id":     []string{"XXX"},
				"state":         []string{"pants"},
			},
			wantACR: AuthCodeRequest{
				ResponseType: "token",
				ClientID:     "XXX",
				Scope:        []string{"foo", "bar", "baz"},
				State:        "pants",
				RedirectURL: &url.URL{
					Scheme:   "https",
					Host:     "127.0.0.1:5555",
					Path:     "/callback",
					RawQuery: "foo=bar",
				},
			},
		},

		// unparseable redirect_uri
		{
			query: url.Values{
				"response_type": []string{"code"},
				"redirect_uri":  []string{":"},
				"scope":         []string{"foo bar baz"},
				"client_id":     []string{"XXX"},
				"state":         []string{"pants"},
			},
			wantACR: AuthCodeRequest{
				ResponseType: "code",
				ClientID:     "XXX",
				Scope:        []string{"foo", "bar", "baz"},
				State:        "pants",
			},
			wantErr: NewError(ErrorInvalidRequest),
		},

		// no client_id, redirect_uri not parsed
		{
			query: url.Values{
				"response_type": []string{"code"},
				"redirect_uri":  []string{"https://127.0.0.1:5555/callback?foo=bar"},
				"scope":         []string{"foo bar baz"},
				"client_id":     []string{},
				"state":         []string{"pants"},
			},
			wantACR: AuthCodeRequest{
				ResponseType: "code",
				ClientID:     "",
				Scope:        []string{"foo", "bar", "baz"},
				State:        "pants",
				RedirectURL:  nil,
			},
			wantErr: NewError(ErrorInvalidRequest),
		},
	}

	for i, tt := range tests {
		got, err := ParseAuthCodeRequest(tt.query)
		if !reflect.DeepEqual(tt.wantErr, err) {
			t.Errorf("case %d: incorrect error value: want=%q got=%q", i, tt.wantErr, err)
		}

		if !reflect.DeepEqual(tt.wantACR, got) {
			t.Errorf("case %d: incorrect AuthCodeRequest value: want=%#v got=%#v", i, tt.wantACR, got)
		}
	}
}

func TestClientIdentityMatch(t *testing.T) {
	tests := []struct {
		a ClientIdentity
		b ClientIdentity
		w bool
	}{
		{
			a: ClientIdentity{ID: "foo", Secret: "bar"},
			b: ClientIdentity{ID: "foo", Secret: "bar"},
			w: true,
		},
		{
			a: ClientIdentity{ID: "foo", Secret: "bar"},
			b: ClientIdentity{ID: "foo", Secret: "baz"},
			w: false,
		},
		{
			a: ClientIdentity{ID: "foo", Secret: "bar"},
			b: ClientIdentity{ID: "baz", Secret: "bar"},
			w: false,
		},
	}

	for i, tt := range tests {
		atob := tt.a.Match(tt.b)
		if tt.w != atob {
			t.Errorf("case %d: a.Match(b): want=%t, got=%t", i, tt.w, atob)
		}

		btoa := tt.b.Match(tt.a)
		if tt.w != btoa {
			t.Errorf("case %d: b.Match(a): want=%t, got=%t", i, tt.w, btoa)
		}
	}
}
