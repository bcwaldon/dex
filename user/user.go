package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"code.google.com/p/go-uuid/uuid"

	"github.com/coreos-inc/auth/jose"
)

type UserIDGenerator func() (string, error)

func DefaultUserIDGenerator() (string, error) {
	return uuid.New(), nil
}

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
}

// AddToClaims adds basic information about the user to the given Claims.
// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
func (u *User) AddToClaims(claims jose.Claims) {
	claims.Add("name", u.DisplayName)
	claims.Add("preferred_username", u.Name)
}

// UserRepo implementations maintain a persistent set of users.
// The following invariants must be maintained:
//  * Users must have a unique Name and ID
//  * ValidName(name)
//  * No other Users may have the same RemoteIdentity as one of the
//    users. (This constraint may be relaxed in the future)
type UserRepo interface {
	Get(id string) (User, error)

	Create(User) (userID string, err error)

	Update(User) error

	GetByRemoteIdentity(RemoteIdentity) (User, error)

	AddRemoteIdentity(userID string, remoteID RemoteIdentity) error

	RemoveRemoteIdentity(userID string, remoteID RemoteIdentity) error

	GetRemoteIdentities(userID string) ([]RemoteIdentity, error)
}

var (
	ErrorDuplicateID             = errors.New("ID not available")
	ErrorDuplicateName           = errors.New("name not available")
	ErrorDuplicateRemoteIdentity = errors.New("remote identity already in use for another user")
	ErrorInvalidID               = errors.New("invalid ID")
	ErrorInvalidName             = errors.New("invalid Name")
	ErrorNotFound                = errors.New("user not found in repository")
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
	return NewUserRepoWithIDGenerator(DefaultUserIDGenerator)
}

// NewUserRepoWithIDGenerator is the same as NewUserRepo but with the ability to provide your own UserIDGenerator.
func NewUserRepoWithIDGenerator(userIDGenerator UserIDGenerator) UserRepo {
	return &memUserRepo{
		usersByID:         make(map[string]User),
		userIDsByName:     make(map[string]string),
		userIDsByRemoteID: make(map[RemoteIdentity]string),
		remoteIDsByUserID: make(map[string]map[RemoteIdentity]struct{}),
		userIDGenerator:   userIDGenerator,
	}
}

type memUserRepo struct {
	usersByID         map[string]User
	userIDsByName     map[string]string
	userIDsByRemoteID map[RemoteIdentity]string
	userIDGenerator   UserIDGenerator
	remoteIDsByUserID map[string]map[RemoteIdentity]struct{}
}

func (r *memUserRepo) Get(id string) (User, error) {
	user, ok := r.usersByID[id]
	if !ok {
		return User{}, ErrorNotFound
	}
	return user, nil
}

func (r *memUserRepo) Create(user User) (string, error) {
	if user.ID != "" {
		return "", ErrorInvalidID
	}

	if !ValidName(user.Name) {
		return "", ErrorInvalidName
	}

	newID, err := r.userIDGenerator()
	if err != nil {
		return "", err
	}

	// make sure no one has the same ID; if using UUID the chances of this
	// happening are astronomically small.
	_, ok := r.usersByID[user.ID]
	if ok {
		return "", ErrorDuplicateID
	}

	// make sure there's no other user with the same Name
	_, ok = r.userIDsByName[user.Name]
	if ok {
		return "", ErrorDuplicateName
	}

	user.ID = newID
	r.set(user)
	return newID, nil
}

func (r *memUserRepo) Update(user User) error {
	if user.ID == "" {
		return ErrorInvalidID
	}

	if !ValidName(user.Name) {
		return ErrorInvalidName
	}

	// make sure this user exists already
	_, ok := r.usersByID[user.ID]
	if !ok {
		return ErrorNotFound
	}

	// make sure there's no other user with the same Name
	otherID, ok := r.userIDsByName[user.Name]
	if ok && otherID != user.ID {
		return ErrorDuplicateName
	}

	r.set(user)
	return nil
}

func (r *memUserRepo) AddRemoteIdentity(userID string, ri RemoteIdentity) error {
	_, ok := r.usersByID[userID]
	if !ok {
		return ErrorNotFound
	}
	_, ok = r.userIDsByRemoteID[ri]
	if ok {
		return ErrorDuplicateRemoteIdentity
	}

	r.userIDsByRemoteID[ri] = userID
	rIDs, ok := r.remoteIDsByUserID[userID]
	if !ok {
		rIDs = make(map[RemoteIdentity]struct{})
		r.remoteIDsByUserID[userID] = rIDs
	}

	rIDs[ri] = struct{}{}
	return nil
}

func (r *memUserRepo) RemoveRemoteIdentity(userID string, ri RemoteIdentity) error {
	otherID, ok := r.userIDsByRemoteID[ri]
	if !ok {
		return ErrorNotFound
	}
	if otherID != userID {
		return ErrorNotFound
	}
	delete(r.userIDsByRemoteID, ri)
	delete(r.remoteIDsByUserID[userID], ri)
	return nil
}

func (r *memUserRepo) GetByRemoteIdentity(ri RemoteIdentity) (User, error) {
	userID, ok := r.userIDsByRemoteID[ri]
	if !ok {
		return User{}, ErrorNotFound
	}

	user, ok := r.usersByID[userID]
	if !ok {
		return User{}, ErrorNotFound
	}
	return user, nil
}

func (r *memUserRepo) GetRemoteIdentities(userID string) ([]RemoteIdentity, error) {
	ids := []RemoteIdentity{}
	for id := range r.remoteIDsByUserID[userID] {
		ids = append(ids, id)
	}
	return ids, nil
}

func (r *memUserRepo) set(user User) error {
	r.usersByID[user.ID] = user
	r.userIDsByName[user.Name] = user.ID
	return nil
}

type UserWithRemoteIdentities struct {
	User             User             `json:"user"`
	RemoteIdentities []RemoteIdentity `json:"remoteIdentities"`
}

// NewUserRepoFromFile returns an in-memory UserRepo useful for development given a JSON serialized file of Users.
func NewUserRepoFromFile(loc string) (UserRepo, error) {
	us, err := readUsersFromFile(loc)
	if err != nil {
		return nil, err
	}
	return NewUserRepoFromUsers(us), nil
}

func NewUserRepoFromUsers(us []UserWithRemoteIdentities) UserRepo {
	memUserRepo := NewUserRepo().(*memUserRepo)
	for _, u := range us {
		memUserRepo.set(u.User)
		for _, ri := range u.RemoteIdentities {
			memUserRepo.AddRemoteIdentity(u.User.ID, ri)
		}
	}
	return memUserRepo
}

func newUsersFromReader(r io.Reader) ([]UserWithRemoteIdentities, error) {
	var us []UserWithRemoteIdentities
	err := json.NewDecoder(r).Decode(&us)
	return us, err
}

func readUsersFromFile(loc string) ([]UserWithRemoteIdentities, error) {
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
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	}

	err := json.Unmarshal(data, &dec)
	if err != nil {
		return fmt.Errorf("invalid User entry: %v", err)
	}

	u.ID = dec.ID
	u.Name = dec.Name
	u.DisplayName = dec.DisplayName

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
