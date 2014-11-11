package oidc

import (
	"github.com/coreos-inc/auth/jose"
)

type Identity struct {
	ID    string
	Name  string
	Email string
}

func IdentityFromClaims(claims jose.Claims) (*Identity, error) {
	//TODO(bcwaldon): check errors from the following type assertions
	return &Identity{
		ID: claims["sub"].(string),
		//Name:  claims["name"].(string),
		Email: claims["email"].(string),
	}, nil
}
