package local

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/coreos-inc/auth/oidc"
)

type user struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (u user) Identity() oidc.Identity {
	return oidc.Identity{
		ID:    u.ID,
		Name:  u.Name,
		Email: u.Email,
	}
}

func NewLocalIdentityProviderFromReader(r io.Reader) (*LocalIdentityProvider, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var us []user
	if err = json.Unmarshal(b, &us); err != nil {
		return nil, err
	}

	idents := make([]oidc.Identity, len(us))
	for i, u := range us {
		idents[i] = u.Identity()
	}

	return NewLocalIdentityProvider(idents), nil
}

func NewLocalIdentityProvider(idents []oidc.Identity) *LocalIdentityProvider {
	p := LocalIdentityProvider{
		idents: make(map[string]oidc.Identity, len(idents)),
	}

	for _, ident := range idents {
		ident := ident
		p.idents[ident.ID] = ident
	}

	return &p
}

type LocalIdentityProvider struct {
	idents map[string]oidc.Identity
}

func (m *LocalIdentityProvider) Identity(id string) *oidc.Identity {
	ident, ok := m.idents[id]
	if !ok {
		return nil
	}
	return &ident
}
