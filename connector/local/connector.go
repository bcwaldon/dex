package local

import (
	"errors"
	"io"
	"net/http"

	"github.com/coreos-inc/auth/oidc"
)

func NewLocalIDPConnector(r io.Reader) (*localIDPConnector, error) {
	p, err := newLocalIdentityProvider(r)
	if err != nil {
		return nil, err
	}
	return &localIDPConnector{p}, nil
}

type localIDPConnector struct {
	*localIdentityProvider
}

func (c *localIDPConnector) DisplayType() string {
	return "Local"
}

func (c *localIDPConnector) Identify(r *http.Request) (*oidc.Identity, error) {
	userID := r.URL.Query().Get("uid")
	if userID == "" {
		return nil, errors.New("missing uid query param")
	}

	u := c.User(userID)
	if u == nil {
		return nil, errors.New("unrecognized user ID")
	}

	ident := oidc.Identity{
		ID:    u.ID,
		Name:  u.Name,
		Email: u.Email,
	}

	return &ident, nil
}
