package oidc

import (
	"errors"
	"fmt"
	"time"

	"github.com/coreos-inc/auth/jose"
)

type Identity struct {
	ID        string
	Name      string
	Email     string
	ExpiresAt time.Time
}

func IdentityFromClaims(claims jose.Claims) (*Identity, error) {
	if claims == nil {
		return nil, errors.New("nil claim set")
	}

	claim := func(k string, required bool) (v string, err error) {
		vi, ok := claims[k]
		if !ok {
			if required {
				err = fmt.Errorf("missing %s claim", k)
			}
			return
		}
		v, ok = vi.(string)
		if !ok {
			err = fmt.Errorf("unparseable %s claim: %v", k, vi)
		}
		return
	}

	var ident Identity
	var err error

	if ident.ID, err = claim("sub", true); err != nil {
		return nil, err
	}
	if ident.Email, err = claim("email", false); err != nil {
		return nil, err
	}

	if exp, ok := claims["exp"]; ok {
		ei, ok := exp.(int64)
		if !ok {
			ef, ok := exp.(float64)
			if !ok {
				return nil, fmt.Errorf("unparseable exp claim: %v", exp)
			}
			ei = int64(ef)
		}
		ident.ExpiresAt = time.Unix(ei, 0).UTC()
	}

	return &ident, nil
}
