package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	phttp "github.com/coreos-inc/auth/pkg/http"
)

type Config struct {
	ClientID     string
	ClientSecret string
	Scope        []string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
}

type Client struct {
	hc          phttp.Client
	identity    ClientIdentity
	scope       []string
	redirectURL *url.URL
	authURL     *url.URL
	tokenURL    *url.URL
}

type ClientIdentity struct {
	ID          string
	Secret      string
	RedirectURL url.URL
}

func (ci ClientIdentity) Match(other ClientIdentity) bool {
	return ci.ID == other.ID && ci.Secret == other.Secret
}

func NewClient(hc phttp.Client, cfg Config) (c *Client, err error) {
	if cfg.ClientID == "" {
		err = errors.New("missing client id")
		return
	}

	if cfg.ClientSecret == "" {
		err = errors.New("missing client secret")
		return
	}

	au, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return
	}

	tu, err := url.Parse(cfg.TokenURL)
	if err != nil {
		return
	}

	ru, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return
	}

	c = &Client{
		identity: ClientIdentity{
			ID:          cfg.ClientID,
			Secret:      cfg.ClientSecret,
			RedirectURL: *ru,
		},
		scope:    cfg.Scope,
		authURL:  au,
		tokenURL: tu,
		hc:       hc,
	}

	return
}

// Generate the url for initial redirect to oauth provider.
func (c *Client) AuthCodeURL(state, accessType, prompt string) string {
	v := c.commonURLValues()
	v.Set("state", state)
	v.Set("access_type", accessType)
	v.Set("approval_prompt", prompt)
	v.Set("response_type", "code")

	q := v.Encode()
	u := *c.authURL
	if u.RawQuery == "" {
		u.RawQuery = q
	} else {
		u.RawQuery += "&" + q
	}
	return u.String()
}

func (c *Client) commonURLValues() url.Values {
	return url.Values{
		"redirect_uri": {c.identity.RedirectURL.String()},
		"scope":        {strings.Join(c.scope, " ")},
		"client_id":    {c.identity.ID},
	}
}

// Exchange auth code for series of tokens.
func (c *Client) Exchange(code string) (result TokenResponse, err error) {
	v := c.commonURLValues()
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)

	// TODO(sym3tri): only pass this in url if provider doesnt use basic auth
	v.Set("client_secret", c.identity.Secret)

	req, err := http.NewRequest("POST", c.tokenURL.String(), strings.NewReader(v.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.SetBasicAuth(c.identity.ID, c.identity.Secret)
	resp, err := c.hc.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err = fmt.Errorf("oauth2: error getting token. code: %d, status: %s.\nResponse: %s", resp.StatusCode, resp.Status, string(body))
		return
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return
	}

	result = TokenResponse{
		RawBody: body,
	}

	if contentType == "application/x-www-form-urlencoded" || contentType == "text/plain" {
		var vals url.Values
		vals, err = url.ParseQuery(string(body))
		if err != nil {
			return
		}
		result.AccessToken = vals.Get("access_token")
		result.TokenType = vals.Get("token_type")
		result.IDToken = vals.Get("id_token")
		e := vals.Get("expires_in")
		if e == "" {
			e = vals.Get("expires")
		}
		result.Expires, err = strconv.Atoi(e)
		if err != nil {
			return
		}
	} else {
		b := make(map[string]interface{})
		if err = json.Unmarshal(body, &b); err != nil {
			return
		}
		result.AccessToken, _ = b["access_token"].(string)
		result.TokenType, _ = b["token_type"].(string)
		result.IDToken, _ = b["id_token"].(string)
		e, ok := b["expires_in"].(int)
		if !ok {
			e, _ = b["expires"].(int)
		}
		result.Expires = e
	}

	return
}

type TokenResponse struct {
	AccessToken string
	TokenType   string
	Expires     int
	IDToken     string
	RawBody     []byte // In case callers need some other non-standard info from the token response
}

type AuthCodeRequest struct {
	ClientID    string
	RedirectURL url.URL
	Scope       []string
}

func ParseAuthCodeRequest(q url.Values) (*AuthCodeRequest, error) {
	if rt := q.Get("response_type"); rt != "code" {
		return nil, fmt.Errorf("response_type %q unsupported", rt)
	}

	redirectURL := q.Get("redirect_uri")
	if redirectURL == "" {
		return nil, errors.New("missing redirect_uri query param")
	}

	ru, err := url.Parse(redirectURL)
	if err != nil {
		return nil, errors.New("redirect_uri query param invalid")
	}

	scope := make([]string, 0)
	qs := strings.TrimSpace(q.Get("scope"))
	if qs != "" {
		scope = strings.Split(qs, " ")
	}

	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, errors.New("missing client_id query param")
	}

	acr := &AuthCodeRequest{
		ClientID:    clientID,
		RedirectURL: *ru,
		Scope:       scope,
	}

	return acr, nil
}
