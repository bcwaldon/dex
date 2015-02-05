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
)

const (
	// amount of time that must pass after the last key sync
	// completes before another attempt may begin
	keySyncWindow = 5 * time.Second
)

var (
	DefaultScope = []string{"openid", "email", "profile"}
)

type ClientCredentials oauth2.ClientCredentials

type ClientIdentity struct {
	Credentials ClientCredentials
	Metadata    ClientMetadata
}

type ClientMetadata struct {
	RedirectURL url.URL
}

type ClientConfig struct {
	HTTPClient     phttp.Client
	Credentials    ClientCredentials
	Scope          []string
	RedirectURL    string
	ProviderConfig ProviderConfig
	KeySet         key.PublicKeySet
}

func NewClient(cfg ClientConfig) (*Client, error) {
	c := Client{
		credentials:    cfg.Credentials,
		httpClient:     cfg.HTTPClient,
		scope:          cfg.Scope,
		redirectURL:    cfg.RedirectURL,
		providerConfig: cfg.ProviderConfig,
		keySet:         cfg.KeySet,
	}

	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}

	if c.scope == nil {
		c.scope = make([]string, len(DefaultScope))
		copy(c.scope, DefaultScope)
	}

	return &c, nil
}

type Client struct {
	httpClient     phttp.Client
	providerConfig ProviderConfig
	credentials    ClientCredentials
	redirectURL    string
	scope          []string
	keySet         key.PublicKeySet

	keySetSyncMutex sync.Mutex
	lastKeySetSync  time.Time
}

func (c *Client) Healthy() error {
	now := time.Now().UTC()

	if c.providerConfig.Empty() {
		return errors.New("oidc client provider config empty")
	}

	if !c.providerConfig.ExpiresAt.IsZero() && c.providerConfig.ExpiresAt.Before(now) {
		return errors.New("oidc client provider config expired")
	}

	return nil
}

func (c *Client) OAuthClient() (*oauth2.Client, error) {
	ocfg := oauth2.Config{
		Credentials: oauth2.ClientCredentials(c.credentials),
		RedirectURL: c.redirectURL,
		AuthURL:     c.providerConfig.AuthEndpoint,
		TokenURL:    c.providerConfig.TokenEndpoint,
		Scope:       c.scope,
	}

	return oauth2.NewClient(c.httpClient, ocfg)
}

func (c *Client) SyncProviderConfig(discoveryURL string) chan struct{} {
	rp := &providerConfigRepo{c}
	r := NewHTTPProviderConfigGetter(c.httpClient, discoveryURL)
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

	r := NewRemotePublicKeyRepo(c.httpClient, c.providerConfig.KeysEndpoint)
	w := &clientKeyRepo{client: c}
	_, err := key.Sync(r, w, clockwork.NewRealClock())
	c.lastKeySetSync = time.Now().UTC()

	return err
}

type providerConfigRepo struct {
	client *Client
}

func (r *providerConfigRepo) Set(cfg ProviderConfig) error {
	r.client.providerConfig = cfg
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
	r.client.keySet = *pks
	return nil
}

func (c *Client) ClientCredsToken(scope []string) (jose.JWT, error) {
	if !c.providerConfig.SupportsGrantType(oauth2.GrantTypeClientCreds) {
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

// Exchange an OAuth2 auth code for an OIDC JWT
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

func (c *Client) Verify(jwt jose.JWT) error {
	var keys func() []key.PublicKey
	if kID, ok := jwt.KeyID(); ok {
		keys = func() (keys []key.PublicKey) {
			if k := c.keySet.Key(kID); k != nil {
				keys = append(keys, *k)
			}
			return
		}
	} else {
		keys = func() []key.PublicKey {
			return c.keySet.Keys()
		}
	}

	reattempt := func() error {
		ok, err := VerifySignature(jwt, keys())
		if ok || err != nil {
			return err
		}

		if err = c.maybeSyncKeys(); err != nil {
			return err
		}

		ok, err = VerifySignature(jwt, keys())
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

	return VerifyClaims(jwt, c.providerConfig.Issuer, c.credentials.ID)
}
