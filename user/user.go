package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/coreos-inc/auth/jose"
)

const (
	MaxNameLength = 100
)

type User struct {
	// ID is the machine-generated, stable, unique identifier for this User.
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

// AddToClaims adds basic information about the user to the given Claims.
// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
func (u *User) AddToClaims(claims jose.Claims) {
	claims.Add("name", u.DisplayName)
	claims.Add("preferred_username", u.Name)
}

type UserRepo interface {
	Get(id string) (User, error)

	// Set persists a User.
	// Set must maintain the following invariants:
	//  * Users must have a unique Name and ID
	//  * ValidName(name)
	//  * No other Users may have the same RemoteIdentity as one of the
	//    users. (This constraint may be relaxed in the future)
	Set(User) error

	GetByRemoteIdentity(RemoteIdentity) (User, error)
}

var (
	ErrorNotFound                = errors.New("user not found in repository")
	ErrorDuplicateName           = errors.New("name not available")
	ErrorDuplicateRemoteIdentity = errors.New("remote identity already in use for another user")
	ErrorInvalidID               = errors.New("invalid ID")
	ErrorInvalidName             = errors.New("invalid Name")
)

// RemoteIdentity represents a User's identity at an IDP.
type RemoteIdentity struct {
	// IDPCID is the identifier of the IDP which hosts this identity.
	ConnectorID string

	// ID is the identifier of this User at the IDP.
	ID string
}

func ValidName(name string) bool {
	return name != "" && len(name) <= MaxNameLength
}

// NewUserRepo returns an in-memory UserRepo useful for development.
func NewUserRepo() UserRepo {
	return &memUserRepo{
		usersByID:       make(map[string]User),
		usersByName:     make(map[string]User),
		usersByRemoteID: make(map[RemoteIdentity]User),
	}
}

type memUserRepo struct {
	usersByID       map[string]User
	usersByName     map[string]User
	usersByRemoteID map[RemoteIdentity]User
}

func (r *memUserRepo) Get(id string) (User, error) {
	user, ok := r.usersByID[id]
	if !ok {
		return User{}, ErrorNotFound
	}
	return user, nil
}

func (r *memUserRepo) Set(user User) error {
	if user.ID == "" {
		return ErrorInvalidID
	}

	if !ValidName(user.Name) {
		return ErrorInvalidName
	}

	// make sure there's no other user with the same Name
	other, ok := r.usersByName[user.Name]
	if ok && other.ID != user.ID {
		return ErrorDuplicateName
	}

	// make sure no one else has any of the same RemoteIdendities
	for _, ri := range user.RemoteIdentities {
		other, ok = r.usersByRemoteID[ri]
		if ok && other.ID != user.ID {
			return ErrorDuplicateRemoteIdentity
		}
	}

	// finally, we can persist.
	r.usersByID[user.ID] = user
	r.usersByName[user.Name] = user
	for _, ri := range user.RemoteIdentities {
		r.usersByRemoteID[ri] = user
	}
	return nil
}

func (r *memUserRepo) GetByRemoteIdentity(ri RemoteIdentity) (User, error) {
	user, ok := r.usersByRemoteID[ri]
	if !ok {
		return User{}, ErrorNotFound
	}
	return user, nil
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
		ConnectorID string `json:"connectorID"`
		ID          string `json:"id"`
	}

	err := json.Unmarshal(data, &dec)
	if err != nil {
		return fmt.Errorf("invalid RemoteIdentity entry: %v", err)
	}

	u.ID = dec.ID
	u.ConnectorID = dec.ConnectorID

	return nil
}
