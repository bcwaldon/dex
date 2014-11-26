package server

import (
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/pkg/health"
)

type ClientIdentityRepo interface {
	health.Checkable
	ClientIdentity(clientID string) *oauth2.ClientIdentity
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

func (cr *memClientIdentityRepo) Healthy() error {
	return nil
}
