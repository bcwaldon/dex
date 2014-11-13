package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

const (
	discoveryConfigPath = "/.well-known/openid-configuration"
)

var (
	TimeFunc     = time.Now
	DefaultScope = []string{"openid", "email", "profile"}
)

func FetchProviderConfig(hc phttp.Client, issuerURL string) (*ProviderConfig, error) {
	req, err := http.NewRequest("GET", issuerURL+discoveryConfigPath, nil)
	if err != nil {
		return nil, err
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// TODO: store cache headers

	var cfg ProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}

	// TODO: error if issuer is not the same as the original issuer url
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation

	return &cfg, nil
}

// Utiltiy to check for a value in a list.
func contains(values []string, val string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}
	return false
}

// Extends the default scopes with additional scopes while avoiding duplicates.
func createScope(scopes []string) []string {
	ms := make([]string, 0)
	for _, s := range scopes {
		if !contains(DefaultScope, s) {
			ms = append(ms, s)
		}
	}

	ms = append(ms, DefaultScope...)
	return ms
}

type Client struct {
	HTTPClient     phttp.Client
	ProviderConfig ProviderConfig
	ClientIdentity oauth2.ClientIdentity
	RedirectURL    string
	Scope          []string

	verifiers map[string]josesig.Verifier
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
		Scope:        c.Scope,
	}

	return oauth2.NewClient(c.getHTTPClient(), ocfg)
}

func (c *Client) PurgeExpiredVerifiers() error {
	// TODO: implement
	return nil
}

func (c *Client) AddVerifier(s josesig.Verifier) error {
	if c.verifiers == nil {
		c.verifiers = make(map[string]josesig.Verifier)
	}
	// replace in list if exists
	c.verifiers[s.ID()] = s
	return nil
}

func (c *Client) FetchKeys() ([]*jose.JWK, error) {
	req, err := http.NewRequest("GET", c.ProviderConfig.KeysEndpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.getHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var decoded map[string][]*jose.JWK
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	keys, ok := decoded["keys"]
	if !ok {
		return nil, errors.New("invalid response from jwks endpoint")
	}

	return keys, nil
}

// Fetch keys, generate appropriate verifier based on signing algorithm, and update the client's cache.
func (c *Client) RefreshKeys() error {
	jwks, err := c.FetchKeys()
	if err != nil {
		return err
	}

	if err := c.PurgeExpiredVerifiers(); err != nil {
		return err
	}

	// TODO: filter by use:"sig" first

	for _, jwk := range jwks {
		v, err := josesig.NewVerifier(*jwk)
		if err != nil {
			return err
		}

		if err = c.AddVerifier(v); err != nil {
			return err
		}
	}

	return nil
}

// verify if a JWT is valid or not
func (c *Client) Verify(jwt jose.JWT) error {
	for _, v := range c.verifiers {
		err := v.Verify(jwt.Signature, []byte(jwt.Data()))
		if err == nil {
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

	// TODO(sym3tri): stuff access token into claims here?
	jwt, err := jose.ParseJWT(t.IDToken)
	if err != nil {
		return jose.JWT{}, err
	}

	return jwt, c.Verify(jwt)
}

// Verify claims in accordance with OIDC spec
// http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
func VerifyClaims(jwt jose.JWT, issuer, clientID string) error {
	now := TimeFunc().Unix()

	claims, err := jwt.Claims()
	if err != nil {
		return err
	}

	// iss REQUIRED. Issuer Identifier for the Issuer of the response.
	// The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
	if iss, exists := claims["iss"].(string); exists {
		// TODO: clean & canonicalize strings
		if !URLEqual(iss, issuer) {
			return fmt.Errorf("invalid claim value: 'iss'. expected=%s, found=%s.", issuer, iss)
		}
	} else {
		return errors.New("missing claim: 'iss'")
	}

	// exp REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
	// The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
	// Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
	// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	// See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
	// TODO: is this method of type conversion safe?
	if exp, exists := claims["exp"].(float64); exists {
		if now > int64(exp) {
			return errors.New("token is expired")
		}
	} else {
		return errors.New("missing claim: 'exp'")
	}

	// sub REQUIRED. Subject Identifier.
	// Locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
	// It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
	if _, exists := claims["sub"].(string); !exists {
		return errors.New("missing claim: 'sub'")
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

func URLEqual(url1, url2 string) bool {
	u1, err := url.Parse(url1)
	if err != nil {
		return false
	}
	u2, err := url.Parse(url2)
	if err != nil {
		return false
	}

	return (u1.Host + u1.Path) == (u2.Host + u2.Path)
}
