package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/health"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/session"
)

type fakeIDPConnector struct {
	loginURL string
}

func (f *fakeIDPConnector) Healthy() error {
	return nil
}

func (f *fakeIDPConnector) DisplayType() string {
	return "Fake"
}

func (f *fakeIDPConnector) LoginURL(sessionKey, prompt string) (string, error) {
	return f.loginURL, nil
}

func (f *fakeIDPConnector) Register(mux *http.ServeMux, errorURL url.URL) {}

func TestHandleAuthFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		hdlr := handleAuthFunc(nil, nil, nil)
		req, err := http.NewRequest(m, "http://example.com", nil)
		if err != nil {
			t.Errorf("case %s: unable to create HTTP request: %v", m, err)
			continue
		}

		w := httptest.NewRecorder()
		hdlr.ServeHTTP(w, req)

		want := http.StatusMethodNotAllowed
		got := w.Code
		if want != got {
			t.Errorf("case %s: expected HTTP %d, got %d", m, want, got)
		}
	}
}

func TestHandleAuthFuncResponses(t *testing.T) {
	idpcs := map[string]connector.IDPConnector{
		"fake": &fakeIDPConnector{loginURL: "http://fake.example.com"},
	}
	srv := &Server{
		IssuerURL:      "http://server.example.com",
		SessionManager: session.NewSessionManager(session.NewSessionRepo(), session.NewSessionKeyRepo()),
		ClientIdentityRepo: NewClientIdentityRepo([]oauth2.ClientIdentity{
			oauth2.ClientIdentity{
				ID:     "XXX",
				Secret: "secrete",
				RedirectURL: url.URL{
					Scheme: "http",
					Host:   "client.example.com",
					Path:   "/callback",
				},
			},
		}),
	}

	tests := []struct {
		query        url.Values
		wantCode     int
		wantLocation string
	}{
		{
			query: url.Values{
				"response_type": []string{"code"},
				"client_id":     []string{"XXX"},
				"idpc_id":       []string{"fake"},
			},
			wantCode:     http.StatusTemporaryRedirect,
			wantLocation: "http://fake.example.com",
		},

		// provided redirect_uri matches client
		{
			query: url.Values{
				"response_type": []string{"code"},
				"redirect_uri":  []string{"http://client.example.com/callback"},
				"client_id":     []string{"XXX"},
				"idpc_id":       []string{"fake"},
			},
			wantCode:     http.StatusTemporaryRedirect,
			wantLocation: "http://fake.example.com",
		},

		// provided redirect_uri does not match client
		{
			query: url.Values{
				"response_type": []string{"code"},
				"redirect_uri":  []string{"http://unrecognized.example.com/callback"},
				"client_id":     []string{"XXX"},
				"idpc_id":       []string{"fake"},
			},
			wantCode: http.StatusBadRequest,
		},

		// nonexistant client_id
		{
			query: url.Values{
				"response_type": []string{"code"},
				"redirect_uri":  []string{"http://client.example.com/callback"},
				"client_id":     []string{"YYY"},
				"idpc_id":       []string{"fake"},
			},
			wantCode: http.StatusBadRequest,
		},

		// unsupported response type, redirects back to client
		{
			query: url.Values{
				"response_type": []string{"token"},
				"client_id":     []string{"XXX"},
				"idpc_id":       []string{"fake"},
			},
			wantCode:     http.StatusTemporaryRedirect,
			wantLocation: "http://client.example.com/callback?error=unsupported_response_type&state=",
		},
	}

	for i, tt := range tests {
		hdlr := handleAuthFunc(srv, idpcs, nil)
		w := httptest.NewRecorder()
		u := fmt.Sprintf("http://server.example.com?%s", tt.query.Encode())
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Errorf("case %d: unable to form HTTP request: %v", i, err)
			continue
		}

		hdlr.ServeHTTP(w, req)
		if tt.wantCode != w.Code {
			t.Errorf("case %d: HTTP code mismatch: want=%d got=%d", i, tt.wantCode, w.Code)
			continue
		}

		gotLocation := w.Header().Get("Location")
		if tt.wantLocation != gotLocation {
			t.Errorf("case %d: HTTP Location header mismatch: want=%s got=%s", i, tt.wantLocation, gotLocation)
		}
	}
}

func TestHandleTokenFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		hdlr := handleTokenFunc(nil)
		req, err := http.NewRequest(m, "http://example.com", nil)
		if err != nil {
			t.Errorf("case %s: unable to create HTTP request: %v", m, err)
			continue
		}

		w := httptest.NewRecorder()
		hdlr.ServeHTTP(w, req)

		want := http.StatusMethodNotAllowed
		got := w.Code
		if want != got {
			t.Errorf("case %s: expected HTTP %d, got %d", m, want, got)
		}
	}
}

func TestHandleDiscoveryFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		hdlr := handleDiscoveryFunc(oidc.ProviderConfig{})
		req, err := http.NewRequest(m, "http://example.com", nil)
		if err != nil {
			t.Errorf("case %s: unable to create HTTP request: %v", m, err)
			continue
		}

		w := httptest.NewRecorder()
		hdlr.ServeHTTP(w, req)

		want := http.StatusMethodNotAllowed
		got := w.Code
		if want != got {
			t.Errorf("case %s: expected HTTP %d, got %d", m, want, got)
		}
	}
}

func TestHandleDiscoveryFunc(t *testing.T) {
	u := "http://server.example.com"
	cfg := oidc.ProviderConfig{
		Issuer:        u,
		AuthEndpoint:  u + HttpPathAuth,
		TokenEndpoint: u + httpPathToken,
		KeysEndpoint:  u + httpPathKeys,

		GrantTypesSupported:               []string{"authorization_code"},
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenAlgValuesSupported:         []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}

	req, err := http.NewRequest("GET", "http://server.example.com", nil)
	if err != nil {
		t.Fatalf("Failed creating HTTP request: err=%v", err)
	}

	w := httptest.NewRecorder()
	hdlr := handleDiscoveryFunc(cfg)
	hdlr.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Incorrect status code: want=200 got=%d", w.Code)
	}

	h := w.Header()

	if ct := h.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Incorrect Content-Type: want=application/json, got %s", ct)
	}

	ttl, ok, err := phttp.CacheControlMaxAge(h.Get("Cache-Control"))
	if err != nil || !ok || ttl <= 0 {
		t.Fatalf("Incorrect Cache-Control: want=existing non-zero, got=%s, error=%v", ttl, err)
	}

	wantBody := `{"issuer":"http://server.example.com","authorization_endpoint":"http://server.example.com/auth","token_endpoint":"http://server.example.com/token","jwks_uri":"http://server.example.com/keys","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_basic"]}`
	gotBody := w.Body.String()
	if wantBody != gotBody {
		t.Fatalf("Incorrect body: want=%s got=%s", wantBody, gotBody)
	}
}

func TestHandleKeysFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		hdlr := handleKeysFunc(nil, clockwork.NewRealClock())
		req, err := http.NewRequest(m, "http://example.com", nil)
		if err != nil {
			t.Errorf("case %s: unable to create HTTP request: %v", m, err)
			continue
		}

		w := httptest.NewRecorder()
		hdlr.ServeHTTP(w, req)

		want := http.StatusMethodNotAllowed
		got := w.Code
		if want != got {
			t.Errorf("case %s: expected HTTP %d, got %d", m, want, got)
		}
	}
}

func TestHandleKeysFunc(t *testing.T) {
	fc := clockwork.NewFakeClock()
	exp := fc.Now().UTC().Add(13 * time.Second)
	km := &StaticKeyManager{
		expiresAt: exp,
		keys: []jose.JWK{
			jose.JWK{
				ID:       "1234",
				Type:     "RSA",
				Alg:      "RS256",
				Use:      "sig",
				Exponent: 65537,
				Modulus:  big.NewInt(int64(5716758339926702)),
			},
			jose.JWK{
				ID:       "5678",
				Type:     "RSA",
				Alg:      "RS256",
				Use:      "sig",
				Exponent: 65537,
				Modulus:  big.NewInt(int64(1234294715519622)),
			},
		},
	}

	req, err := http.NewRequest("GET", "http://server.example.com", nil)
	if err != nil {
		t.Fatalf("Failed creating HTTP request: err=%v", err)
	}

	w := httptest.NewRecorder()
	hdlr := handleKeysFunc(km, fc)
	hdlr.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Incorrect status code: want=200 got=%d", w.Code)
	}

	wantHeader := http.Header{
		"Content-Type":  []string{"application/json"},
		"Cache-Control": []string{"public, max-age=13"},
		"Expires":       []string{exp.Format(time.RFC1123)},
	}
	gotHeader := w.Header()
	if !reflect.DeepEqual(wantHeader, gotHeader) {
		t.Fatalf("Incorrect headers: want=%#v got=%#v", wantHeader, gotHeader)
	}

	wantBody := `{"keys":[{"kid":"1234","kty":"RSA","alg":"RS256","use":"sig","e":"AAAAAAABAAE=","n":"FE9chh46rg=="},{"kid":"5678","kty":"RSA","alg":"RS256","use":"sig","e":"AAAAAAABAAE=","n":"BGKVohEShg=="}]}`
	gotBody := w.Body.String()
	if wantBody != gotBody {
		t.Fatalf("Incorrect body: want=%s got=%s", wantBody, gotBody)
	}
}

func TestWriteTokenError(t *testing.T) {
	tests := []struct {
		err        error
		state      string
		wantCode   int
		wantHeader http.Header
		wantBody   string
	}{
		{
			err:      oauth2.NewError(oauth2.ErrorInvalidRequest),
			state:    "bazinga",
			wantCode: http.StatusBadRequest,
			wantHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			wantBody: `{"error":"invalid_request","state":"bazinga"}`,
		},
		{
			err:      oauth2.NewError(oauth2.ErrorInvalidRequest),
			wantCode: http.StatusBadRequest,
			wantHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			wantBody: `{"error":"invalid_request"}`,
		},
		{
			err:      oauth2.NewError(oauth2.ErrorInvalidGrant),
			wantCode: http.StatusBadRequest,
			wantHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			wantBody: `{"error":"invalid_grant"}`,
		},
		{
			err:      oauth2.NewError(oauth2.ErrorInvalidClient),
			wantCode: http.StatusUnauthorized,
			wantHeader: http.Header{
				"Content-Type":     []string{"application/json"},
				"Www-Authenticate": []string{"Basic"},
			},
			wantBody: `{"error":"invalid_client"}`,
		},
		{
			err:      oauth2.NewError(oauth2.ErrorServerError),
			wantCode: http.StatusBadRequest,
			wantHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			wantBody: `{"error":"server_error"}`,
		},
		{
			err:      oauth2.NewError(oauth2.ErrorUnsupportedGrantType),
			wantCode: http.StatusBadRequest,
			wantHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			wantBody: `{"error":"unsupported_grant_type"}`,
		},
		{
			err:      errors.New("generic failure"),
			wantCode: http.StatusBadRequest,
			wantHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			wantBody: `{"error":"server_error"}`,
		},
	}

	for i, tt := range tests {
		w := httptest.NewRecorder()
		writeTokenError(w, tt.err, tt.state)

		if tt.wantCode != w.Code {
			t.Errorf("case %d: incorrect HTTP status: want=%d got=%d", i, tt.wantCode, w.Code)
		}

		gotHeader := w.Header()
		if !reflect.DeepEqual(tt.wantHeader, gotHeader) {
			t.Errorf("case %d: incorrect HTTP headers: want=%#v got=%#v", i, tt.wantHeader, gotHeader)
		}

		gotBody := w.Body.String()
		if tt.wantBody != gotBody {
			t.Errorf("case %d: incorrect HTTP body: want=%q got=%q", i, tt.wantBody, gotBody)
		}
	}
}

func TestWriteAuthError(t *testing.T) {
	wantCode := http.StatusBadRequest
	wantHeader := http.Header{"Content-Type": []string{"application/json"}}
	tests := []struct {
		err      error
		state    string
		wantBody string
	}{
		{
			err:      errors.New("foobar"),
			state:    "bazinga",
			wantBody: `{"error":"server_error","state":"bazinga"}`,
		},
		{
			err:      oauth2.NewError(oauth2.ErrorInvalidRequest),
			state:    "foo",
			wantBody: `{"error":"invalid_request","state":"foo"}`,
		},
		{
			err:      oauth2.NewError(oauth2.ErrorUnsupportedResponseType),
			state:    "bar",
			wantBody: `{"error":"unsupported_response_type","state":"bar"}`,
		},
	}

	for i, tt := range tests {
		w := httptest.NewRecorder()
		writeAuthError(w, tt.err, tt.state)

		if wantCode != w.Code {
			t.Errorf("case %d: incorrect HTTP status: want=%d got=%d", i, wantCode, w.Code)
		}

		gotHeader := w.Header()
		if !reflect.DeepEqual(wantHeader, gotHeader) {
			t.Errorf("case %d: incorrect HTTP headers: want=%#v got=%#v", i, wantHeader, gotHeader)
		}

		gotBody := w.Body.String()
		if tt.wantBody != gotBody {
			t.Errorf("case %d: incorrect HTTP body: want=%q got=%q", i, tt.wantBody, gotBody)
		}
	}
}

func TestRedirectAuthError(t *testing.T) {
	wantCode := http.StatusTemporaryRedirect

	tests := []struct {
		err         error
		state       string
		redirectURL url.URL
		wantLoc     string
	}{
		{
			err:         errors.New("foobar"),
			state:       "bazinga",
			redirectURL: url.URL{Scheme: "http", Host: "server.example.com"},
			wantLoc:     "http://server.example.com?error=server_error&state=bazinga",
		},
		{
			err:         oauth2.NewError(oauth2.ErrorInvalidRequest),
			state:       "foo",
			redirectURL: url.URL{Scheme: "http", Host: "server.example.com"},
			wantLoc:     "http://server.example.com?error=invalid_request&state=foo",
		},
		{
			err:         oauth2.NewError(oauth2.ErrorUnsupportedResponseType),
			state:       "bar",
			redirectURL: url.URL{Scheme: "http", Host: "server.example.com"},
			wantLoc:     "http://server.example.com?error=unsupported_response_type&state=bar",
		},
	}

	for i, tt := range tests {
		w := httptest.NewRecorder()
		redirectAuthError(w, tt.err, tt.state, tt.redirectURL)

		if wantCode != w.Code {
			t.Errorf("case %d: incorrect HTTP status: want=%d got=%d", i, wantCode, w.Code)
		}

		wantHeader := http.Header{"Location": []string{tt.wantLoc}}
		gotHeader := w.Header()
		if !reflect.DeepEqual(wantHeader, gotHeader) {
			t.Errorf("case %d: incorrect HTTP headers: want=%#v got=%#v", i, wantHeader, gotHeader)
		}

		gotBody := w.Body.String()
		if gotBody != "" {
			t.Errorf("case %d: incorrect empty HTTP body, got=%q", i, gotBody)
		}
	}
}

func TestShouldReprompt(t *testing.T) {
	tests := []struct {
		c *http.Cookie
		v bool
	}{
		// No cookie
		{
			c: nil,
			v: false,
		},
		// different cookie
		{
			c: &http.Cookie{
				Name: "rando-cookie",
			},
			v: false,
		},
		// actual cookie we care about
		{
			c: &http.Cookie{
				Name: "LastSeen",
			},
			v: true,
		},
	}

	for i, tt := range tests {
		r := &http.Request{Header: make(http.Header)}
		if tt.c != nil {
			r.AddCookie(tt.c)
		}
		want := tt.v
		got := shouldReprompt(r)
		if want != got {
			t.Errorf("case %d: want=%t, got=%t", i, want, got)
		}
	}
}

type checkable struct {
	healthy bool
}

func (c checkable) Healthy() (err error) {
	if !c.healthy {
		err = errors.New("im unhealthy")
	}
	return
}

func TestHandleHealthFunc(t *testing.T) {
	tests := []struct {
		checks      []health.Checkable
		wantCode    int
		wantMessage string
	}{
		{
			checks:      []health.Checkable{checkable{false}},
			wantMessage: "fail",
			wantCode:    http.StatusInternalServerError,
		},
		{
			checks:      []health.Checkable{checkable{true}},
			wantMessage: "ok",
			wantCode:    http.StatusOK,
		},
	}

	for i, tt := range tests {
		hdlr := handleHealthFunc(tt.checks)
		r, _ := http.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		hdlr(w, r)

		if tt.wantCode != w.Code {
			t.Errorf("case %d: want=%d, got=%d", i, tt.wantCode, w.Code)
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Errorf("case %d: unexpected error=%v", i, err)
		}

		got := resp["message"]
		if tt.wantMessage != got {
			t.Errorf("case %d: want=%s, got=%s", i, tt.wantMessage, got)
		}
	}
}
