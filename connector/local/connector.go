package local

import (
	"errors"
	"net/http"

	"github.com/coreos-inc/auth/oidc"
)

type LocalIDPConnector struct {
	*LocalIdentityProvider
}

func (c *LocalIDPConnector) DisplayType() string {
	return "Local"
}

func (c *LocalIDPConnector) Identify(r *http.Request) (*oidc.Identity, error) {
	id := r.URL.Query().Get("uid")
	if id == "" {
		return nil, errors.New("missing uid query param")
	}

	ident := c.Identity(id)
	if ident == nil {
		return nil, errors.New("unrecognized uid")
	}

	return ident, nil
}
