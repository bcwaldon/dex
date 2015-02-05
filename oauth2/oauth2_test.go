package oauth2

import (
	"errors"
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

func TestClientCredsToken(t *testing.T) {
	hc := &phttp.RequestRecorder{Error: errors.New("error")}
	cfg := Config{
		Credentials: ClientCredentials{ID: "cid", Secret: "csecret"},
		Scope:       []string{"foo-scope", "bar-scope"},
		TokenURL:    "http://example.com/token",
	}

	c, err := NewClient(hc, cfg)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	scope := []string{"openid"}
	c.ClientCredsToken(scope)
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

	if cfg.Credentials.ID != cid {
		t.Errorf("wrong client ID, want=%v, got=%v", cfg.Credentials.ID, cid)
	}

	if cfg.Credentials.Secret != secret {
		t.Errorf("wrong client secret, want=%v, got=%v", cfg.Credentials.Secret, secret)
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
	if !reflect.DeepEqual(scope, sc) {
		t.Errorf("wrong scope, want=%v, got=%v", scope, sc)
	}
}
