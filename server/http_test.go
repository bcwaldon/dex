package server

import (
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

type fakeIDPConnector struct {
	loginURL string
}

func (f *fakeIDPConnector) DisplayType() string {
	return "Fake"
}

func (f *fakeIDPConnector) LoginURL(sessionKey string) (string, error) {
	return f.loginURL, nil
}

func (f *fakeIDPConnector) Register(mux *http.ServeMux) {}

func TestHandleAuthFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		hdlr := handleAuthFunc(nil, nil)
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
	idpc := &fakeIDPConnector{loginURL: "http://fake.example.com"}
	signer := &StaticSigner{sig: []byte("beer"), err: nil}
	srv := &Server{
		IssuerURL:      "http://server.example.com",
		Signer:         signer,
		SessionManager: NewSessionManager("http://fake.example.com", signer),
		ClientIdentityRepo: NewClientIdentityRepo([]oauth2.ClientIdentity{
			oauth2.ClientIdentity{ID: "XXX", Secret: "secrete"},
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
				"redirect_uri":  []string{"http://client.example.com/callback"},
				"client_id":     []string{"XXX"},
			},
			wantCode:     http.StatusTemporaryRedirect,
			wantLocation: "http://fake.example.com",
		},

		// nonexistant client_id
		{
			query: url.Values{
				"response_type": []string{"code"},
				"redirect_uri":  []string{"http://client.example.com/callback"},
				"client_id":     []string{"YYY"},
			},
			wantCode: http.StatusBadRequest,
		},

		// ParseAuthCodeRequest should fail
		{
			query: url.Values{
				"response_type": []string{"token"},
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for i, tt := range tests {
		hdlr := handleAuthFunc(srv, idpc)
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
		AuthEndpoint:  u + httpPathAuth,
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

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Incorrect Content-Type: want=application/json, got %s", ct)
	}

	wantBody := `{"issuer":"http://server.example.com","authorization_endpoint":"http://server.example.com/auth","token_endpoint":"http://server.example.com/token","jwks_uri":"http://server.example.com/keys","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_basic"]}`
	gotBody := w.Body.String()
	if wantBody != gotBody {
		t.Fatalf("Incorrect body: want=%s got=%s", wantBody, gotBody)
	}
}

func TestHandleKeysFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		hdlr := handleKeysFunc([]jose.JWK{})
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
	keys := []jose.JWK{
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
	}

	req, err := http.NewRequest("GET", "http://server.example.com", nil)
	if err != nil {
		t.Fatalf("Failed creating HTTP request: err=%v", err)
	}

	w := httptest.NewRecorder()
	hdlr := handleKeysFunc(keys)
	hdlr.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Incorrect status code: want=200 got=%d", w.Code)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Incorrect Content-Type: want=application/json, got %s", ct)
	}

	wantBody := `{"keys":[{"kid":"1234","kty":"RSA","alg":"RS256","use":"sig","e":"AAAAAAABAAE=","n":"FE9chh46rg=="},{"kid":"5678","kty":"RSA","alg":"RS256","use":"sig","e":"AAAAAAABAAE=","n":"BGKVohEShg=="}]}`
	gotBody := w.Body.String()
	if wantBody != gotBody {
		t.Fatalf("Incorrect body: want=%s got=%s", wantBody, gotBody)
	}
}
