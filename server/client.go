package server

import (
	"github.com/coreos-inc/auth/oauth2"
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
