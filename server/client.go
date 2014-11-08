package server

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/coreos-inc/auth/oauth2"
)

type ClientIdentityRepo interface {
	ClientIdentity(clientID string) *oauth2.ClientIdentity
}

func NewClientIdentityRepoFromReader(r io.Reader) (ClientIdentityRepo, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var cs []oauth2.ClientIdentity
	if err = json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}

	return NewClientIdentityRepo(cs), nil
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

func (cr *memClientIdentityRepo) ClientIdentity(clientID string) *oauth2.ClientIdentity {
	ci, ok := cr.idents[clientID]
	if !ok {
		return nil
	}
	return &ci
}
