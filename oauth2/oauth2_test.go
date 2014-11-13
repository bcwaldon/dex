package oauth2

import (
	"net/url"
	"reflect"
	"testing"
)

func TestParseAuthCodeRequest(t *testing.T) {
	q := url.Values{
		"response_type": []string{"code"},
		"redirect_uri":  []string{"https://127.0.0.1:5555/callback?foo=bar"},
		"scope":         []string{"foo bar baz"},
		"client_id":     []string{"XXX"},
		"state":         []string{"pants"},
	}

	want := AuthCodeRequest{
		ClientID: "XXX",
		Scope:    []string{"foo", "bar", "baz"},
		State:    "pants",
		RedirectURL: url.URL{
			Scheme:   "https",
			Host:     "127.0.0.1:5555",
			Path:     "/callback",
			RawQuery: "foo=bar",
		},
	}

	got, err := ParseAuthCodeRequest(q)
	if err != nil {
		t.Fatalf("err=%v", err)
	}

	if !reflect.DeepEqual(want, *got) {
		t.Fatalf("want=%#v got=%#v", want, *got)
	}
}

func TestParseAuthCodeRequestInvalid(t *testing.T) {
	tests := []url.Values{
		// unsupported response_type
		url.Values{
			"response_type": []string{"token"},
			"redirect_uri":  []string{"https://127.0.0.1:5555/callback?foo=bar"},
			"scope":         []string{"foo bar baz"},
			"client_id":     []string{"XXX"},
		},

		// no redirect_uri
		url.Values{
			"response_type": []string{"code"},
			"redirect_uri":  []string{},
			"scope":         []string{"foo bar baz"},
			"client_id":     []string{"XXX"},
		},

		// unparseable redirect_uri
		url.Values{
			"response_type": []string{"code"},
			"redirect_uri":  []string{":"},
			"scope":         []string{"foo bar baz"},
			"client_id":     []string{"XXX"},
		},

		// no client_id
		url.Values{
			"response_type": []string{"code"},
			"redirect_uri":  []string{"https://127.0.0.1:5555/callback?foo=bar"},
			"scope":         []string{"foo bar baz"},
			"client_id":     []string{},
		},
	}

	for i, q := range tests {
		_, err := ParseAuthCodeRequest(q)
		if err == nil {
			t.Errorf("case %d: want non-nil error, got nil", i)
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
