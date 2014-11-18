package oidc

import (
	"errors"
	"github.com/coreos-inc/auth/jose"
)

type Identity struct {
	ID    string
	Name  string
	Email string
}

func IdentityFromClaims(claims jose.Claims) (*Identity, error) {
	if claims == nil {
		return nil, errors.New("invalid claim set")
	}

	//TODO(bcwaldon): check errors from the following type assertions
	return &Identity{
		ID: claims["sub"].(string),
		//Name:  claims["name"].(string),
		Email: claims["email"].(string),
	}, nil
}
