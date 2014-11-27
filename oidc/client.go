package oidc

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	phttp "github.com/coreos-inc/auth/pkg/http"
	pnet "github.com/coreos-inc/auth/pkg/net"
)

var (
	DefaultScope = []string{"openid", "email", "profile"}
)

func ParseTokenFromRequest(r *http.Request) (token jose.JWT, err error) {
	ah := r.Header.Get("Authorization")
	if ah == "" {
		err = errors.New("missing Authorization header")
		return
	}

	if len(ah) <= 6 || strings.ToUpper(ah[0:6]) != "BEARER" {
		err = errors.New("should be a bearer token")
		return
	}

	return jose.ParseJWT(ah[7:])
}

type Client struct {
	HTTPClient     phttp.Client
	ProviderConfig ProviderConfig
	ClientIdentity oauth2.ClientIdentity
	RedirectURL    string
	Scope          []string
	Keys           []key.PublicKey
}

func (c *Client) Healthy() error {
	if c.ProviderConfig.ExpiresAt.Before(time.Now().UTC()) {
		return errors.New("oidc client provider config expired")
	}

	// TODO(sym3tri): consider using keyset to track key expiration
	if len(c.Keys) == 0 {
		return errors.New("oidc client missing public keys")
	}

	return nil
}

func (c *Client) getHTTPClient() phttp.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) getScope() []string {
	if c.Scope != nil {
		return c.Scope
	}
	return DefaultScope
}

func (c *Client) OAuthClient() (*oauth2.Client, error) {
	ocfg := oauth2.Config{
		RedirectURL:  c.RedirectURL,
		ClientID:     c.ClientIdentity.ID,
		ClientSecret: c.ClientIdentity.Secret,
		AuthURL:      c.ProviderConfig.AuthEndpoint,
		TokenURL:     c.ProviderConfig.TokenEndpoint,
		Scope:        c.getScope(),
	}

	return oauth2.NewClient(c.getHTTPClient(), ocfg)
}

func (c *Client) SyncProviderConfig() chan struct{} {
	rp := &providerConfigRepo{c}
	r := NewHTTPProviderConfigGetter(c.getHTTPClient(), c.ProviderConfig.Issuer)
	return NewProviderConfigSyncer(r, rp).Run()
}

func (c *Client) SyncKeys() chan struct{} {
	r := newRemotePublicKeyRepo(c.getHTTPClient(), c.ProviderConfig.KeysEndpoint)
	w := &clientKeyRepo{client: c}
	return key.NewKeySetSyncer(r, w).Run()
}

type providerConfigRepo struct {
	client *Client
}

func (r *providerConfigRepo) Set(cfg ProviderConfig) error {
	r.client.ProviderConfig = cfg
	return nil
}

type clientKeyRepo struct {
	client *Client
}

func (r *clientKeyRepo) Set(ks key.KeySet) error {
	pks, ok := ks.(*key.PublicKeySet)
	if !ok {
		return errors.New("unable to cast to PublicKey")
	}
	r.client.Keys = pks.Keys()
	return nil
}

// verify if a JWT is valid or not
func (c *Client) Verify(jwt jose.JWT) error {
	for _, k := range c.Keys {
		v, err := k.Verifier()
		if err != nil {
			return err
		}
		if v.Verify(jwt.Signature, []byte(jwt.Data())) == nil {
			return VerifyClaims(jwt, c.ProviderConfig.Issuer, c.ClientIdentity.ID)
		}
	}

	return errors.New("could not verify JWT signature")
}

// Exchange an OAauth2 auth code for an OIDC JWT
func (c *Client) ExchangeAuthCode(code string) (jose.JWT, error) {
	oac, err := c.OAuthClient()
	if err != nil {
		return jose.JWT{}, err
	}

	t, err := oac.Exchange(code)
	if err != nil {
		return jose.JWT{}, err
	}

	jwt, err := jose.ParseJWT(t.IDToken)
	if err != nil {
		return jose.JWT{}, err
	}

	return jwt, c.Verify(jwt)
}

// Verify claims in accordance with OIDC spec
// http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
func VerifyClaims(jwt jose.JWT, issuer, clientID string) error {
	now := time.Now().UTC()

	claims, err := jwt.Claims()
	if err != nil {
		return err
	}

	ident, err := IdentityFromClaims(claims)
	if err != nil {
		return err
	}

	if ident.ExpiresAt.Before(now) {
		return errors.New("token is expired")
	}

	// iss REQUIRED. Issuer Identifier for the Issuer of the response.
	// The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
	if iss, exists := claims["iss"].(string); exists {
		// TODO: clean & canonicalize strings
		if !pnet.URLEqual(iss, issuer) {
			return fmt.Errorf("invalid claim value: 'iss'. expected=%s, found=%s.", issuer, iss)
		}
	} else {
		return errors.New("missing claim: 'iss'")
	}

	// iat REQUIRED. Time at which the JWT was issued.
	// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	if _, exists := claims["iat"].(float64); !exists {
		return errors.New("missing claim: 'iat'")
	}

	// aud REQUIRED. Audience(s) that this ID Token is intended for.
	// It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
	if aud, exists := claims["aud"].(string); exists {
		// TODO: clean & canonicalize strings
		if aud != clientID {
			return errors.New("invalid claim value: 'aud'")
		}
	} else {
		return errors.New("missing claim: 'aud'")
	}

	// TODO: optional claims from OIDC spec
	// auth_time, nonce, at_hash, acr, amr, azp

	return nil
}
