package connector

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/coreos-inc/auth/oauth2"
	o "github.com/coreos-inc/auth/oidc"
)

func TestLoginURL(t *testing.T) {
	lf := func(ident o.Identity, sessionKey string) (redirectURL string, err error) { return }

	tests := []struct {
		cid    string
		redir  string
		state  string
		scope  []string
		prompt string
		v      url.Values
	}{
		// Standard example
		{
			cid:    "fake-client-id",
			redir:  "http://example.com/oauth-redirect",
			state:  "fake-session-id",
			scope:  []string{"openid", "email", "profile"},
			prompt: "",
			v: url.Values{
				"response_type": {"code"},
				"state":         {"fake-session-id"},
				"redirect_uri":  {"http://example.com/oauth-redirect"},
				"scope":         {"openid email profile"},
				"client_id":     {"fake-client-id"},
			},
		},
		// No scope
		{
			cid:    "fake-client-id",
			redir:  "http://example.com/oauth-redirect",
			state:  "fake-session-id",
			scope:  []string{},
			prompt: "",
			v: url.Values{
				"response_type": {"code"},
				"state":         {"fake-session-id"},
				"redirect_uri":  {"http://example.com/oauth-redirect"},
				"scope":         {""},
				"client_id":     {"fake-client-id"},
			},
		},
		// No state
		{
			cid:    "fake-client-id",
			redir:  "http://example.com/oauth-redirect",
			state:  "",
			scope:  []string{},
			prompt: "",
			v: url.Values{
				"response_type": {"code"},
				"state":         {""},
				"redirect_uri":  {"http://example.com/oauth-redirect"},
				"scope":         {""},
				"client_id":     {"fake-client-id"},
			},
		},
		// Force prompt
		{
			cid:    "fake-client-id",
			redir:  "http://example.com/oauth-redirect",
			state:  "fake-session-id",
			scope:  []string{"openid", "email", "profile"},
			prompt: "force",
			v: url.Values{
				"response_type":   {"code"},
				"approval_prompt": {"force"},
				"state":           {"fake-session-id"},
				"redirect_uri":    {"http://example.com/oauth-redirect"},
				"scope":           {"openid email profile"},
				"client_id":       {"fake-client-id"},
			},
		},
	}

	for i, tt := range tests {
		cl := &o.Client{
			ClientIdentity: oauth2.ClientIdentity{ID: tt.cid, Secret: "fake-client-secret"},
			RedirectURL:    tt.redir,
			Scope:          tt.scope,
		}
		cn := &OIDCConnector{
			loginFunc: lf,
			client:    cl,
		}

		lu, err := cn.LoginURL(tt.state, tt.prompt)
		if err != nil {
			t.Errorf("test: %d. want: no url error, got: error, error: %v", i, err)
		}

		u, err := url.Parse(lu)
		if err != nil {
			t.Errorf("test: %d. want: parsable url, got: unparsable url, error: %v", i, err)
		}

		got := u.Query()
		if !reflect.DeepEqual(tt.v, got) {
			t.Errorf("test: %d.\nwant: %v\ngot:  %v", i, tt.v, got)
		}
	}
}
