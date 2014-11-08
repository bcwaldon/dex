package local

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func newLocalIdentityProvider(r io.Reader) (*localIdentityProvider, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var us []User
	if err = json.Unmarshal(b, &us); err != nil {
		return nil, err
	}

	p := localIdentityProvider{
		users: make(map[string]User, len(us)),
	}

	for _, u := range us {
		u := u
		p.users[u.ID] = u
	}

	return &p, nil
}

type localIdentityProvider struct {
	users map[string]User
}

func (m *localIdentityProvider) User(id string) *User {
	u, ok := m.users[id]
	if !ok {
		return nil
	}
	return &u
}
