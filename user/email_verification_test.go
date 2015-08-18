package user

import (
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/kylelemons/godebug/pretty"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
)

func TestNewEmailVerification(t *testing.T) {
	clock = clockwork.NewFakeClock()
	defer func() {
		clock = clockwork.NewRealClock()
	}()

	now := clock.Now()

	issuer, _ := url.Parse("http://example.com")
	clientID := "myclient"
	usr := User{ID: "123456", Email: "user@example.com"}
	callback := "http://client.example.com/callback"
	expires := time.Hour * 3

	tests := []struct {
		issuer   url.URL
		user     User
		clientID string
		callback string
		expires  time.Duration
		want     jose.Claims
	}{
		{
			issuer:   *issuer,
			clientID: clientID,
			user:     usr,
			callback: callback,
			expires:  expires,
			want: map[string]interface{}{
				"iss": issuer.String(),
				"aud": clientID,
				ClaimEmailVerificationCallback: callback,
				ClaimEmailVerificationEmail:    usr.Email,
				"exp": float64(now.Add(expires).Unix()),
				"sub": usr.ID,
				"iat": float64(now.Unix()),
			},
		},
	}

	for i, tt := range tests {
		cbURL, err := url.Parse(tt.callback)
		if err != nil {
			t.Fatalf("case %d: non-nil err: %q", i, err)
		}
		ev := NewEmailVerification(tt.user, tt.clientID, tt.issuer, *cbURL, tt.expires)

		if diff := pretty.Compare(tt.want, ev.claims); diff != "" {
			t.Errorf("case %d: Compare(want, got): %v", i, diff)
		}

	}
}

func TestEmailVerificationParseAndVerify(t *testing.T) {

	issuer, _ := url.Parse("http://example.com")
	otherIssuer, _ := url.Parse("http://bad.example.com")
	client := "myclient"
	user := User{ID: "1234", Email: "user@example.com"}
	callback, _ := url.Parse("http://client.example.com")
	expires := time.Hour * 3

	goodEV := NewEmailVerification(user, client, *issuer, *callback, expires)
	expiredEV := NewEmailVerification(user, client, *issuer, *callback, -expires)
	wrongIssuerEV := NewEmailVerification(user, client, *otherIssuer, *callback, expires)
	noSubEV := NewEmailVerification(User{}, client, *issuer, *callback, expires)

	privKey, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key, error=%v", err)
	}
	signer := privKey.Signer()

	privKey2, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key, error=%v", err)
	}
	otherSigner := privKey2.Signer()

	tests := []struct {
		ev      EmailVerification
		wantErr bool
		signer  jose.Signer
	}{

		{
			ev:      goodEV,
			signer:  signer,
			wantErr: false,
		},
		{
			ev:      expiredEV,
			signer:  signer,
			wantErr: true,
		},
		{
			ev:      wrongIssuerEV,
			signer:  signer,
			wantErr: true,
		},
		{
			ev:      goodEV,
			signer:  otherSigner,
			wantErr: true,
		},
		{
			ev:      noSubEV,
			signer:  signer,
			wantErr: true,
		},
	}

	for i, tt := range tests {

		token, err := tt.ev.Token(tt.signer)
		if err != nil {
			t.Errorf("case %d: non-nil error creating token: %v", i, err)
		}

		ev, err := ParseAndVerifyEmailVerificationToken(token, *issuer,
			[]key.PublicKey{*key.NewPublicKey(privKey.JWK())})

		if tt.wantErr {
			t.Logf("err: %v", err)
			if err == nil {
				t.Errorf("case %d: want non-nil err, got nil", i)
			}
			continue
		}

		if err != nil {
			t.Errorf("case %d: non-nil err: %q", i, err)

		}

		if diff := pretty.Compare(tt.ev.claims, ev.claims); diff != "" {
			t.Errorf("case %d: Compare(want, got): %v", i, diff)
		}
	}
}
