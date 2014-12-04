package local

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/coreos-inc/auth/oidc"
)

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u User) Identity() oidc.Identity {
	return oidc.Identity{
		ID:    u.ID,
		Name:  u.Name,
		Email: u.Email,
	}
}

func ReadUsersFromFile(loc string) ([]User, error) {
	uf, err := os.Open(loc)
	if err != nil {
		return nil, fmt.Errorf("unable to read users from file %q: %v", loc, err)
	}
	defer uf.Close()

	b, err := ioutil.ReadAll(uf)
	if err != nil {
		return nil, err
	}

	var us []User
	err = json.Unmarshal(b, &us)
	return us, err
}

func NewLocalIdentityProvider(users []User) *LocalIdentityProvider {
	p := LocalIdentityProvider{
		users: make(map[string]User, len(users)),
	}

	for _, u := range users {
		u := u
		p.users[u.ID] = u
	}

	return &p
}

type LocalIdentityProvider struct {
	users map[string]User
}

func (m *LocalIdentityProvider) Identity(id, password string) *oidc.Identity {
	u, ok := m.users[id]
	if !ok || u.Password != password {
		return nil
	}

	ident := u.Identity()
	return &ident
}
