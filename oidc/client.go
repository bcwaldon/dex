package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
)

const (
	discoveryConfigPath = "/.well-known/openid-configuration"
)

var TimeFunc = time.Now

func FetchProviderConfig(issuerURL string) (*ProviderConfig, error) {
	configEndpoint := fmt.Sprintf("%s%s", issuerURL, discoveryConfigPath)

	configBody, err := httpGet(configEndpoint)
	if err != nil {
		return nil, err
	}

	// TODO: store cache headers

	var cfg ProviderConfig
	if err := json.Unmarshal(configBody, &cfg); err != nil {
		return nil, err
	}

	// TODO: error if issuer is not the same as the original issuer url
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation

	return &cfg, nil
}

type Client struct {
	ProviderConfig ProviderConfig
	ClientIdentity oauth2.ClientIdentity
	OAuthClient    oauth2.Client
	Verifiers      map[string]josesig.Verifier // Cached store of verifiers.
}

func NewClient(cfg ProviderConfig, ci oauth2.ClientIdentity, redirectURL string) (*Client, error) {
	// TODO: error if missing required config
	oac, err := oauth2.NewClient(oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     ci.ID,
		ClientSecret: ci.Secret,
		AuthURL:      cfg.AuthEndpoint,
		TokenURL:     cfg.TokenEndpoint,
		// TODO(sym3tri): need concpet of default scope, and allow user to extend
		Scope: []string{"openid", "email", "profile"},
	})
	if err != nil {
		return nil, err
	}

	c := &Client{
		ProviderConfig: cfg,
		ClientIdentity: ci,
		OAuthClient:    *oac,
		Verifiers:      make(map[string]josesig.Verifier),
	}

	return c, nil
}

// helper
func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

// TODO: move
func (c *Client) PurgeExpiredVerifiers() error {
	// TODO: implement
	return nil
}

// TODO: move
func (c *Client) AddVerifier(s josesig.Verifier) error {
	// replace in list if exists
	c.Verifiers[s.ID()] = s
	return nil
}

// Fetch keys from JWKs endpoint.
func (c *Client) FetchKeys() ([]*jose.JWK, error) {
	keyBytes, err := httpGet(c.ProviderConfig.JWKSURI)
	if err != nil {
		return nil, err
	}

	var jsonData map[string][]*jose.JWK
	err = json.NewDecoder(bytes.NewReader(keyBytes)).Decode(&jsonData)
	if err != nil {
		return nil, err
	}

	keys, exists := jsonData["keys"]
	if !exists {
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
	for _, v := range c.Verifiers {
		err := v.Verify(jwt.Signature, []byte(jwt.Data()))
		if err == nil {
			return VerifyClaims(jwt, c.ProviderConfig.Issuer, c.ClientIdentity.ID)
		}
	}

	return errors.New("could not verify JWT signature")
}

// Exchange an OAauth2 auth code for an OIDC JWT
func (c *Client) ExchangeAuthCode(code string) (jose.JWT, error) {
	t, err := c.OAuthClient.Exchange(code)
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
