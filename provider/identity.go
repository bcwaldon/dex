package provider

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

type User struct {
	ID    string
	Name  string
	Email string
}

type IdentityProvider interface {
	User(id string) *User
}

type localIdentityProvider struct {
	users map[string]User
}

func NewIdentityProviderFromReader(r io.Reader) (IdentityProvider, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var us []User
	if err = json.Unmarshal(b, &us); err != nil {
		return nil, err
	}

	m := localIdentityProvider{
		users: make(map[string]User, len(us)),
	}

	for _, u := range us {
		u := u
		m.users[u.ID] = u
	}

	return &m, nil
}

func (m *localIdentityProvider) User(id string) *User {
	u, ok := m.users[id]
	if !ok {
		return nil
	}
	return &u
}
