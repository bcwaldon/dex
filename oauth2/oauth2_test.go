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
	}

	want := AuthCodeRequest{
		ClientID: "XXX",
		Scope:    []string{"foo", "bar", "baz"},
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
