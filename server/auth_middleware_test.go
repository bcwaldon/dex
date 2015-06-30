package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oidc"
)

type staticHandler struct{}

func (h staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestClientToken(t *testing.T) {
	now := time.Now()
	tomorrow := now.Add(24 * time.Hour)
	validClientID := "valid-client"
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID: validClientID,
		},
	}
	repo := NewClientIdentityRepo([]oidc.ClientIdentity{ci})

	privKey, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key, error=%v", err)
	}
	signer := privKey.Signer()
	pubKey := *key.NewPublicKey(privKey.JWK())

	validIss := "https://example.com"

	makeToken := func(iss, sub, aud string, iat, exp time.Time) string {
		claims := oidc.NewClaims(iss, sub, aud, iat, exp)
		jwt, err := jose.NewSignedJWT(claims, signer)
		if err != nil {
			t.Fatalf("Failed to generate JWT, error=%v", err)
		}
		return jwt.Encode()
	}

	validJWT := makeToken(validIss, validClientID, validClientID, now, tomorrow)
	invalidJWT := makeToken("", "", "", now, tomorrow)

	tests := []struct {
		keys     []key.PublicKey
		repo     ClientIdentityRepo
		header   string
		wantCode int
	}{
		// valid token
		{
			keys:     []key.PublicKey{pubKey},
			repo:     repo,
			header:   fmt.Sprintf("BEARER %s", validJWT),
			wantCode: http.StatusOK,
		},
		// invalid token
		{
			keys:     []key.PublicKey{pubKey},
			repo:     repo,
			header:   fmt.Sprintf("BEARER %s", invalidJWT),
			wantCode: http.StatusUnauthorized,
		},
		// empty header
		{
			keys:     []key.PublicKey{pubKey},
			repo:     repo,
			header:   "",
			wantCode: http.StatusUnauthorized,
		},
		// unparsable token
		{
			keys:     []key.PublicKey{pubKey},
			repo:     repo,
			header:   "BEARER xxx",
			wantCode: http.StatusUnauthorized,
		},
		// no verification keys
		{
			keys:     []key.PublicKey{},
			repo:     repo,
			header:   fmt.Sprintf("BEARER %s", validJWT),
			wantCode: http.StatusUnauthorized,
		},
		// nil repo
		{
			keys:     []key.PublicKey{pubKey},
			repo:     nil,
			header:   fmt.Sprintf("BEARER %s", validJWT),
			wantCode: http.StatusUnauthorized,
		},
		// empty repo
		{
			keys:     []key.PublicKey{pubKey},
			repo:     NewClientIdentityRepo(nil),
			header:   fmt.Sprintf("BEARER %s", validJWT),
			wantCode: http.StatusUnauthorized,
		},
		// client not in repo
		{
			keys:     []key.PublicKey{pubKey},
			repo:     repo,
			header:   fmt.Sprintf("BEARER %s", makeToken(validIss, "DOESNT-EXIST", "DOESNT-EXIST", now, tomorrow)),
			wantCode: http.StatusUnauthorized,
		},
	}

	for i, tt := range tests {
		w := httptest.NewRecorder()
		mw := &clientTokenMiddleware{
			issuerURL: validIss,
			ciRepo:    tt.repo,
			keysFunc: func() ([]key.PublicKey, error) {
				return tt.keys, nil
			},
			next: staticHandler{},
		}
		req := &http.Request{
			Header: http.Header{
				"Authorization": []string{tt.header},
			},
		}

		mw.ServeHTTP(w, req)
		if tt.wantCode != w.Code {
			t.Errorf("case %d: invalid response code, want=%d, got=%d", i, tt.wantCode, w.Code)
		}
	}
}

func TestGetClientIDFromAuthorizedRequest(t *testing.T) {
	now := time.Now()
	tomorrow := now.Add(24 * time.Hour)

	privKey, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key, error=%v", err)
	}

	signer := privKey.Signer()

	makeToken := func(iss, sub, aud string, iat, exp time.Time) string {
		claims := oidc.NewClaims(iss, sub, aud, iat, exp)
		jwt, err := jose.NewSignedJWT(claims, signer)
		if err != nil {
			t.Fatalf("Failed to generate JWT, error=%v", err)
		}
		return jwt.Encode()
	}

	tests := []struct {
		header     string
		wantClient string
		wantErr    bool
	}{
		{
			header:     fmt.Sprintf("BEARER %s", makeToken("iss", "CLIENT_ID", "", now, tomorrow)),
			wantClient: "CLIENT_ID",
			wantErr:    false,
		},
		{
			header:  fmt.Sprintf("BEARER %s", makeToken("iss", "", "", now, tomorrow)),
			wantErr: true,
		},
	}

	for i, tt := range tests {
		req := &http.Request{
			Header: http.Header{
				"Authorization": []string{tt.header},
			},
		}
		gotClient, err := getClientIDFromAuthorizedRequest(req)
		if tt.wantErr {
			if err == nil {
				t.Errorf("case %d: want non-nil err", i)
			}
			continue
		}

		if err != nil {
			t.Errorf("case %d: got err: %q", i, err)
			continue
		}

		if gotClient != tt.wantClient {
			t.Errorf("case %d: want=%v, got=%v", i, tt.wantClient, gotClient)
		}
	}
}
