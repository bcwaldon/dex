package oauth2

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	phttp "github.com/coreos-inc/auth/pkg/http"
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

func TestClientToken(t *testing.T) {
	hc := &phttp.RequestRecorder{}
	cfg := Config{
		ClientID:     "cid",
		ClientSecret: "csecret",
		Scope:        []string{"foo-scope", "bar-scope"},
		TokenURL:     "http://example.com/token",
	}

	c, err := NewClient(hc, cfg)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	c.ClientToken()
	if hc.Request == nil {
		t.Error("request is empty")
	}

	tu := hc.Request.URL.String()
	if cfg.TokenURL != tu {
		t.Errorf("wrong token url, want=%v, got=%v", cfg.TokenURL, tu)
	}

	ct := hc.Request.Header.Get("Content-Type")
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("wrong content-type, want=application/x-www-form-urlencoded, got=%v", ct)
	}

	cid, secret, ok := phttp.BasicAuth(hc.Request)
	if !ok {
		t.Error("unexpected error parsing basic auth")
	}

	if cfg.ClientID != cid {
		t.Errorf("wrong client ID, want=%v, got=%v", cfg.ClientID, cid)
	}

	if cfg.ClientSecret != secret {
		t.Errorf("wrong client secret, want=%v, got=%v", cfg.ClientSecret, secret)
	}

	err = hc.Request.ParseForm()
	if err != nil {
		t.Error("unexpected error parsing form")
	}

	gt := hc.Request.PostForm.Get("grant_type")
	if gt != GrantTypeClientCreds {
		t.Errorf("wrong grant_type, want=client_credentials, got=%v", gt)
	}

	sc := strings.Split(hc.Request.PostForm.Get("scope"), " ")
	if !reflect.DeepEqual(cfg.Scope, sc) {
		t.Errorf("wrong scope, want=%v, got=%v", cfg.Scope, sc)
	}
}
