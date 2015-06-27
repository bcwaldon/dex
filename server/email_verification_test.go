package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oidc"
)

func TestHandleVerifyEmailResend(t *testing.T) {
	now := time.Now()
	tomorrow := now.Add(24 * time.Hour)
	yesterday := now.Add(-24 * time.Hour)

	privKey, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key, error=%v", err)
	}

	signer := privKey.Signer()
	signerFunc := func() (jose.Signer, error) {
		return signer, nil
	}

	pubKey := *key.NewPublicKey(privKey.JWK())
	keysFunc := func() ([]key.PublicKey, error) {
		return []key.PublicKey{pubKey}, nil
	}

	makeToken := func(iss, sub, aud string, iat, exp time.Time) string {
		claims := oidc.NewClaims(iss, sub, aud, iat, exp)
		jwt, err := jose.NewSignedJWT(claims, signer)
		if err != nil {
			t.Fatalf("Failed to generate JWT, error=%v", err)
		}
		return jwt.Encode()
	}

	verifyURL := url.URL{Scheme: "http", Host: "example.com", Path: "/verify"}

	tests := []struct {
		bearerJWT   string
		userJWT     string
		redirectURL url.URL
		wantCode    int
	}{
		{
			// The happy case
			bearerJWT: makeToken(testIssuerURL.String(),
				testClientID, testClientID, now, tomorrow),
			userJWT: makeToken(testIssuerURL.String(),
				"ID-1", testClientID, now, tomorrow),
			redirectURL: testRedirectURL,
			wantCode:    http.StatusOK,
		},
		{
			// Expired userJWT
			bearerJWT: makeToken(testIssuerURL.String(),
				testClientID, testClientID, now, tomorrow),
			userJWT: makeToken(testIssuerURL.String(),
				"ID-1", testClientID, now, yesterday),
			redirectURL: testRedirectURL,
			wantCode:    http.StatusUnauthorized,
		},
		{
			// Client ID is unknown
			bearerJWT: makeToken(testIssuerURL.String(),
				"fakeclientid", testClientID, now, tomorrow),
			userJWT: makeToken(testIssuerURL.String(),
				"ID-1", testClientID, now, tomorrow),
			redirectURL: testRedirectURL,
			wantCode:    http.StatusBadRequest,
		},
		{
			// No sub in user JWT
			bearerJWT: makeToken(testIssuerURL.String(),
				testClientID, testClientID, now, tomorrow),
			userJWT: makeToken(testIssuerURL.String(),
				"", testClientID, now, tomorrow),
			redirectURL: testRedirectURL,
			wantCode:    http.StatusBadRequest,
		},
		{
			// Unknown user
			bearerJWT: makeToken(testIssuerURL.String(),
				testClientID, testClientID, now, tomorrow),
			userJWT: makeToken(testIssuerURL.String(),
				"NonExistent", testClientID, now, tomorrow),
			redirectURL: testRedirectURL,
			wantCode:    http.StatusBadRequest,
		},
		{
			// No redirect URL
			bearerJWT: makeToken(testIssuerURL.String(),
				testClientID, testClientID, now, tomorrow),
			userJWT: makeToken(testIssuerURL.String(),
				"ID-1", testClientID, now, tomorrow),
			redirectURL: url.URL{},
			wantCode:    http.StatusBadRequest,
		},
	}

	for i, tt := range tests {
		f, err := makeTestFixtures()
		if err != nil {
			t.Fatalf("case %d: could not make test fixtures: %v", i, err)
		}

		hdlr := handleVerifyEmailResendFunc(
			testIssuerURL,
			verifyURL,
			time.Hour*1,
			keysFunc,
			signerFunc,
			f.emailer,
			"bob@example.com",
			f.userRepo,
			f.clientIdentityRepo)

		w := httptest.NewRecorder()
		u := "http://example.com"
		q := struct {
			Token       string `json:"token"`
			RedirectURI string `json:"redirect_uri"`
		}{
			Token:       tt.userJWT,
			RedirectURI: tt.redirectURL.String(),
		}
		qBytes, err := json.Marshal(&q)
		if err != nil {
			t.Errorf("case %d: unable to marshal JSON: %q", i, err)
		}

		req, err := http.NewRequest("POST", u, bytes.NewReader(qBytes))
		req.Header.Set("Authorization", "Bearer "+tt.bearerJWT)

		if err != nil {
			t.Errorf("case %d: unable to form HTTP request: %v", i, err)
		}

		hdlr.ServeHTTP(w, req)
		if tt.wantCode != w.Code {
			t.Errorf("case %d: wantCode=%v, got=%v", i, tt.wantCode, w.Code)
			t.Logf("case %d: response body was: %v", i, w.Body.String())
		}

	}
}
