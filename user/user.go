package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type User struct {
	// ID is the machine-generated, stable identifier for this User.
	ID string

	// Name is a human readable identifier for a User.
	// Name must be unique within a UserRepo.
	// Prefer ID, as this might change over the lifetime of a User.
	Name string

	// DisplayName is human readable name meant for display purposes.
	// DisplayName is not neccesarily unique with a UserRepo.
	DisplayName string

	// RemoteIdentities are the identities this User has on various IDPs.
	RemoteIdentities []RemoteIdentity
}

type UserRepo interface {
	Get(id string) (User, error)
	Set(User) error
}

var ErrNotFound = errors.New("user not found in repository")

// RemoteIdentity represents a User's identity at an IDP.
type RemoteIdentity struct {
	// IDPCID is the identifier of the IDP which hosts this identity.
	IDPCID string

	// ID is the identifier of this User at the IDP.
	ID string
}

// NewUserRepo returns an in-memory UserRepo useful for development.
func NewUserRepo() UserRepo {
	return &memUserRepo{
		usersByID: make(map[string]User),
	}
}

type memUserRepo struct {
	usersByID map[string]User
}

func (r *memUserRepo) Get(id string) (User, error) {
	user, ok := r.usersByID[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return user, nil
}

func (r *memUserRepo) Set(user User) error {
	r.usersByID[user.ID] = user
	return nil
}

// NewUserRepoFromFile returns an in-memory UserRepo useful for development given a JSON serialized file of Users.
func NewUserRepoFromFile(loc string) (UserRepo, error) {
	us, err := readUsersFromFile(loc)
	if err != nil {
		return nil, err
	}
	return newUserRepoFromUsers(us), nil
}

func newUserRepoFromUsers(us []User) UserRepo {
	memUserRepo := NewUserRepo()
	for _, u := range us {
		memUserRepo.Set(u)
	}
	return memUserRepo
}

func newUsersFromReader(r io.Reader) ([]User, error) {
	var us []User
	err := json.NewDecoder(r).Decode(&us)
	return us, err
}

func readUsersFromFile(loc string) ([]User, error) {
	uf, err := os.Open(loc)
	if err != nil {
		return nil, fmt.Errorf("unable to read users from file %q: %v", loc, err)
	}
	defer uf.Close()

	us, err := newUsersFromReader(uf)
	if err != nil {
		return nil, err
	}

	return us, err
}

func (u *User) UnmarshalJSON(data []byte) error {
	var dec struct {
		ID               string           `json:"id"`
		Name             string           `json:"name"`
		DisplayName      string           `json:"displayName"`
		RemoteIdentities []RemoteIdentity `json:"remoteIdentities"`
	}

	err := json.Unmarshal(data, &dec)
	if err != nil {
		return fmt.Errorf("invalid User entry: %v", err)
	}

	u.ID = dec.ID
	u.Name = dec.Name
	u.DisplayName = dec.DisplayName
	u.RemoteIdentities = dec.RemoteIdentities

	return nil
}

func (u *RemoteIdentity) UnmarshalJSON(data []byte) error {
	var dec struct {
		IDPCID string `json:"idpcID"`
		ID     string `json:"id"`
	}

	err := json.Unmarshal(data, &dec)
	if err != nil {
		return fmt.Errorf("invalid RemoteIdentity entry: %v", err)
	}

	u.ID = dec.ID
	u.IDPCID = dec.IDPCID

	return nil
}
