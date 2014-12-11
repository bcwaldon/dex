package server

import (
	"encoding/json"
	"github.com/coreos-inc/auth/oauth2"
	"io"
	"io/ioutil"
	"net/url"
)

type ClientIdentityRepo interface {
	// Find returns one matching ClientIdentity if exists, otherwise nil.
	// The returned error will be non-nil only if the repo was unable to
	// determine ClientIdentity existence.
	Find(clientID string) (*oauth2.ClientIdentity, error)
}

func NewClientIdentityRepo(cs []oauth2.ClientIdentity) ClientIdentityRepo {
	cr := memClientIdentityRepo{
		idents: make(map[string]oauth2.ClientIdentity, len(cs)),
	}

	for _, c := range cs {
		c := c
		cr.idents[c.ID] = c
	}

	return &cr
}

type memClientIdentityRepo struct {
	idents map[string]oauth2.ClientIdentity
}

func (cr *memClientIdentityRepo) Find(clientID string) (*oauth2.ClientIdentity, error) {
	ci, ok := cr.idents[clientID]
	if !ok {
		return nil, nil
	}
	return &ci, nil
}

func newClientIdentityRepoFromReader(r io.Reader) (ClientIdentityRepo, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var cs []clientIdentity
	if err = json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}

	ocs := make([]oauth2.ClientIdentity, len(cs))
	for i, c := range cs {
		ocs[i] = oauth2.ClientIdentity(c)
	}

	return NewClientIdentityRepo(ocs), nil
}

type clientIdentity oauth2.ClientIdentity

func (ci *clientIdentity) UnmarshalJSON(data []byte) error {
	c := struct {
		ID          string `json:"id"`
		Secret      string `json:"secret"`
		RedirectURL string `json:"redirectURL"`
	}{}

	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}

	ru, err := url.Parse(c.RedirectURL)
	if err != nil {
		return err
	}

	ci.ID = c.ID
	ci.Secret = c.Secret
	ci.RedirectURL = *ru

	return nil
}
