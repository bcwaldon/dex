package oidc

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	phttp "github.com/coreos-inc/auth/pkg/http"
	pnet "github.com/coreos-inc/auth/pkg/net"
)

const (
	// amount of time that must pass after the last key sync
	// completes before another attempt may begin
	keySyncWindow = 5 * time.Second
)

var (
	DefaultScope = []string{"openid", "email", "profile"}
)

type Client struct {
	HTTPClient     phttp.Client
	ProviderConfig ProviderConfig
	Credentials    oauth2.ClientCredentials
	RedirectURL    string
	Scope          []string
	KeySet         key.PublicKeySet

	keySetSyncMutex sync.Mutex
	lastKeySetSync  time.Time
}

type ClientIdentity struct {
	Credentials oauth2.ClientCredentials
	Metadata    ClientMetadata
}

type ClientMetadata struct {
	RedirectURL url.URL
}

func (c *Client) Healthy() error {
	now := time.Now().UTC()

	if c.ProviderConfig.ExpiresAt.IsZero() {
		return errors.New("oidc client provider config not initialized")
	}

	if c.ProviderConfig.ExpiresAt.Before(now) {
		return errors.New("oidc client provider config expired")
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
		Credentials: c.Credentials,
		RedirectURL: c.RedirectURL,
		AuthURL:     c.ProviderConfig.AuthEndpoint,
		TokenURL:    c.ProviderConfig.TokenEndpoint,
		Scope:       c.getScope(),
	}

	return oauth2.NewClient(c.getHTTPClient(), ocfg)
}

func (c *Client) SyncProviderConfig(discoveryURL string) chan struct{} {
	rp := &providerConfigRepo{c}
	r := NewHTTPProviderConfigGetter(c.getHTTPClient(), discoveryURL)
	return NewProviderConfigSyncer(r, rp).Run()
}

func (c *Client) maybeSyncKeys() error {
	tooSoon := func() bool {
		return time.Now().UTC().Before(c.lastKeySetSync.Add(keySyncWindow))
	}

	// ignore request to sync keys if a sync operation has been
	// attempted too recently
	if tooSoon() {
		return nil
	}

	c.keySetSyncMutex.Lock()
	defer c.keySetSyncMutex.Unlock()

	// check again, as another goroutine may have been holding
	// the lock while updating the keys
	if tooSoon() {
		return nil
	}

	r := NewRemotePublicKeyRepo(c.getHTTPClient(), c.ProviderConfig.KeysEndpoint)
	w := &clientKeyRepo{client: c}
	_, err := key.Sync(r, w, clockwork.NewRealClock())
	c.lastKeySetSync = time.Now().UTC()

	return err
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
	r.client.KeySet = *pks
	return nil
}

// verify if a JWT is valid or not
func (c *Client) Verify(jwt jose.JWT) error {
	var keys func() []key.PublicKey
	if kID, ok := jwt.KeyID(); ok {
		keys = func() (keys []key.PublicKey) {
			if k := c.KeySet.Key(kID); k != nil {
				keys = append(keys, *k)
			}
			return
		}
	} else {
		keys = func() []key.PublicKey {
			return c.KeySet.Keys()
		}
	}

	jwtBytes := []byte(jwt.Data())

	attempt := func() (bool, error) {
		for _, k := range keys() {
			v, err := k.Verifier()
			if err != nil {
				return false, err
			}
			if v.Verify(jwt.Signature, jwtBytes) == nil {
				return true, nil
			}
		}
		return false, nil
	}

	reattempt := func() error {
		ok, err := attempt()
		if ok || err != nil {
			return err
		}

		if err = c.maybeSyncKeys(); err != nil {
			return err
		}

		ok, err = attempt()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("no matching keys")
		}

		return nil
	}

	if err := reattempt(); err != nil {
		return fmt.Errorf("could not verify JWT signature: %v", err)
	}

	return VerifyClaims(jwt, c.ProviderConfig.Issuer, c.Credentials.ID)
}

func (c *Client) ClientCredsToken(scope []string) (jose.JWT, error) {
	if !c.ProviderConfig.SupportsGrantType(oauth2.GrantTypeClientCreds) {
		return jose.JWT{}, fmt.Errorf("%v grant type is not supported", oauth2.GrantTypeClientCreds)
	}

	oac, err := c.OAuthClient()
	if err != nil {
		return jose.JWT{}, err
	}

	t, err := oac.ClientCredsToken(scope)
	if err != nil {
		return jose.JWT{}, err
	}

	jwt, err := jose.ParseJWT(t.IDToken)
	if err != nil {
		return jose.JWT{}, err
	}

	return jwt, c.Verify(jwt)
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
		if aud != clientID {
			return errors.New("invalid claim value: 'aud'")
		}
	} else {
		return errors.New("missing claim: 'aud'")
	}

	return nil
}
