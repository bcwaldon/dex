package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	// TODO: remove
	"log"
	"net/http"

	//"github.com/golang/auth2"
	"code.google.com/p/goauth2/oauth"
)

type Result struct {
	State  string
	Claims map[string]string
	JWT    JWT
}

type Client struct {
	Name           string          // Name of OIDC issuer
	IssuerURL      string          // Base URL of the issuer
	ClientID       string          // OAuth Client ID
	ClientSecret   string          // OAuth Client Secret
	RedirectURL    string          // OAuth Redirect URL
	ProviderConfig *ProviderConfig // OIDC Provider config
	OAuthConfig    *oauth.Config   // OAuth specific config
	// TODO: move this to separate interface/type
	Signers map[string]Signer // Cached store of signers.
}

func NewClient(name, issuerURL, clientID, clientSecret, redirectURL string) *Client {
	// TODO: error if missing required config
	return &Client{
		Name:         name,
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Signers:      make(map[string]Signer),
	}
}

// helper
func Get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func (self *Client) FetchProviderConfig() (*ProviderConfig, error) {
	configEndpoint := fmt.Sprintf("%s/%s", self.IssuerURL, discoveryConfigPath)
	fmt.Println(configEndpoint)

	configBody, err := Get(configEndpoint)
	if err != nil {
		return nil, err
	}

	// TODO: store cache headers

	err = json.NewDecoder(bytes.NewReader(configBody)).Decode(&self.ProviderConfig)
	if err != nil {
		return nil, err
	}

	// TODO: error if issuer is not the same as the original issuer url
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation

	fmt.Printf("issuer: %s\n", self.ProviderConfig.Issuer)
	fmt.Printf("user info: %s\n", self.ProviderConfig.UserInfoEndpoint)

	self.configureOAuth()

	return self.ProviderConfig, nil
}

func (self *Client) configureOAuth() {
	self.OAuthConfig = &oauth.Config{
		RedirectURL:  self.RedirectURL,
		Scope:        "openid email profile",
		ClientId:     self.ClientID,
		ClientSecret: self.ClientSecret,
		AuthURL:      self.ProviderConfig.AuthEndpoint,
		TokenURL:     self.ProviderConfig.TokenEndpoint,
	}
}

// TODO: move
func (self *Client) PurgeExpiredSigners() error {
	// TODO: implement
	return nil
}

// TODO: move
func (self *Client) AddSigner(s Signer) error {
	// replace in list if exists
	self.Signers[s.ID()] = s
	return nil
}

// Fetch keys from JWKs endpoint.
func (self *Client) FetchKeys() ([]JWK, error) {
	keyBytes, err := Get(self.ProviderConfig.JWKSURI)
	if err != nil {
		return nil, err
	}

	var jsonData map[string][]JWK
	err = json.NewDecoder(bytes.NewReader(keyBytes)).Decode(&jsonData)
	if err != nil {
		return nil, err
	}

	keys, exists := jsonData["keys"]
	if !exists {
		return nil, errors.New("invalid response from jwks endpoint")
	}

	// TODO: set 'expires' field

	log.Printf("%+v", keys)
	return keys, nil
}

// Fetch keys, generate appropriate signer based on signing algorithm, and update the client's cache.
func (self *Client) RefreshKeys() error {
	jwks, err := self.FetchKeys()
	if err != nil {
		return err
	}

	if err := self.PurgeExpiredSigners(); err != nil {
		return err
	}

	// TODO: filter by use:"sig" first

	for _, k := range jwks {
		s, err := MakeSigner(k)
		if err != nil {
			return err
		}

		err = self.AddSigner(s)
		if err != nil {
			return err
		}
	}

	return nil
}

// verify if a JWT is valid or not
func (self *Client) Verify(jwt JWT) error {
	for _, signer := range self.Signers {
		err := signer.Verify(jwt.Signature, jwt.RawData())
		if err == nil {
			return nil
		}
	}

	return errors.New("could not verify JWT")
}

// Redirect user to providers auth page
func (self *Client) SendToAuthPage(w http.ResponseWriter, r *http.Request, state string) error {
	url := self.OAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

// handle oauth callback
func (self *Client) HandleCallback(r *http.Request) (Result, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return Result{}, errors.New("missing oauth code")
	}

	transport := &oauth.Transport{Config: self.OAuthConfig}
	token, err := transport.Exchange(code)
	if err != nil {
		return Result{}, err
	}

	jwt, err := ParseJWT(token.Extra["id_token"])
	if err != nil {
		return Result{}, err
	}

	if err = self.Verify(jwt); err != nil {
		return Result{}, err
	}

	result := Result{
		State: r.URL.Query().Get("state"),
		JWT:   jwt,
	}

	return result, nil
}
