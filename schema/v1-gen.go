// Package schema provides access to the Authd API.
//
// See http://github.com/coreos-inc/auth
//
// Usage example:
//
//   import "github.com/coreos-inc/auth/Godeps/_workspace/src/google.golang.org/api/schema/v1"
//   ...
//   schemaService, err := schema.New(oauthHttpClient)
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos-inc/auth/Godeps/_workspace/src/google.golang.org/api/googleapi"
)

// Always reference these packages, just in case the auto-generated code
// below doesn't.
var _ = bytes.NewBuffer
var _ = strconv.Itoa
var _ = fmt.Sprintf
var _ = json.NewDecoder
var _ = io.Copy
var _ = url.Parse
var _ = googleapi.Version
var _ = errors.New
var _ = strings.Replace

const apiId = "authd:v1"
const apiName = "schema"
const apiVersion = "v1"
const basePath = "$ENDPOINT/api/v1/"

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Clients = NewClientsService(s)
	return s, nil
}

type Service struct {
	client   *http.Client
	BasePath string // API endpoint base URL

	Clients *ClientsService
}

func NewClientsService(s *Service) *ClientsService {
	rs := &ClientsService{s: s}
	return rs
}

type ClientsService struct {
	s *Service
}

type Client struct {
	Client_id string `json:"client_id,omitempty"`

	Client_name string `json:"client_name,omitempty"`

	Redirect_uris []string `json:"redirect_uris,omitempty"`
}

type ClientPage struct {
	Clients []*Client `json:"clients,omitempty"`

	NextPageToken string `json:"nextPageToken,omitempty"`
}

type ClientWithSecret struct {
	Client_id string `json:"client_id,omitempty"`

	Client_name string `json:"client_name,omitempty"`

	Client_secret string `json:"client_secret,omitempty"`

	Redirect_uris []string `json:"redirect_uris,omitempty"`
}

type Error struct {
	Error string `json:"error,omitempty"`

	Error_description string `json:"error_description,omitempty"`
}

// method id "authd.Client.Create":

type ClientsCreateCall struct {
	s      *Service
	client *Client
	opt_   map[string]interface{}
}

// Create: Register a new Client.
func (r *ClientsService) Create(client *Client) *ClientsCreateCall {
	c := &ClientsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.client = client
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ClientsCreateCall) Fields(s ...googleapi.Field) *ClientsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

func (c *ClientsCreateCall) Do() (*ClientWithSecret, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.client)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", "json")
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "clients")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "google-api-go-client/0.5")
	res, err := c.s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	var ret *ClientWithSecret
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Register a new Client.",
	//   "httpMethod": "POST",
	//   "id": "authd.Client.Create",
	//   "path": "clients",
	//   "request": {
	//     "$ref": "Client"
	//   },
	//   "response": {
	//     "$ref": "ClientWithSecret"
	//   }
	// }

}

// method id "authd.Client.List":

type ClientsListCall struct {
	s    *Service
	opt_ map[string]interface{}
}

// List: Retrieve a page of Client objects.
func (r *ClientsService) List() *ClientsListCall {
	c := &ClientsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// NextPageToken sets the optional parameter "nextPageToken":
func (c *ClientsListCall) NextPageToken(nextPageToken string) *ClientsListCall {
	c.opt_["nextPageToken"] = nextPageToken
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ClientsListCall) Fields(s ...googleapi.Field) *ClientsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

func (c *ClientsListCall) Do() (*ClientPage, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", "json")
	if v, ok := c.opt_["nextPageToken"]; ok {
		params.Set("nextPageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "clients")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", "google-api-go-client/0.5")
	res, err := c.s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	var ret *ClientPage
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Retrieve a page of Client objects.",
	//   "httpMethod": "GET",
	//   "id": "authd.Client.List",
	//   "parameters": {
	//     "nextPageToken": {
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "clients",
	//   "response": {
	//     "$ref": "ClientPage"
	//   }
	// }

}
