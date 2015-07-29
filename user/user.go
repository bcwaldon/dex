package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"

	"code.google.com/p/go-uuid/uuid"

	"github.com/coreos-inc/auth/repo"
	"github.com/coreos/go-oidc/jose"
)

const (
	MaxEmailLength = 200
)

type UserIDGenerator func() (string, error)

func DefaultUserIDGenerator() (string, error) {
	return uuid.New(), nil
}

type User struct {
	// ID is the machine-generated, stable, unique identifier for this User.
	ID string

	// DisplayName is human readable name meant for display purposes.
	// DisplayName is not neccesarily unique with a UserRepo.
	DisplayName string

	Email string

	EmailVerified bool

	Admin bool
}

// AddToClaims adds basic information about the user to the given Claims.
// http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
func (u *User) AddToClaims(claims jose.Claims) {
	claims.Add("name", u.DisplayName)
	if u.Email != "" {
		claims.Add("email", u.Email)
		if u.EmailVerified {
			claims.Add("email_verified", true)
		}
	}
}

// UserRepo implementations maintain a persistent set of users.
// The following invariants must be maintained:
//  * Users must have a unique Email and ID
//  * No other Users may have the same RemoteIdentity as one of the
//    users. (This constraint may be relaxed in the future)
type UserRepo interface {
	Get(tx repo.Transaction, id string) (User, error)

	Create(repo.Transaction, User) error

	GetByEmail(tx repo.Transaction, email string) (User, error)

	Update(repo.Transaction, User) error

	GetByRemoteIdentity(repo.Transaction, RemoteIdentity) (User, error)

	AddRemoteIdentity(tx repo.Transaction, userID string, remoteID RemoteIdentity) error

	RemoveRemoteIdentity(tx repo.Transaction, userID string, remoteID RemoteIdentity) error

	GetRemoteIdentities(tx repo.Transaction, userID string) ([]RemoteIdentity, error)

	GetAdminCount(repo.Transaction) (int, error)
}

var (
	ErrorDuplicateID    = errors.New("ID not available")
	ErrorDuplicateEmail = errors.New("email not available")

	ErrorDuplicateRemoteIdentity = errors.New("remote identity already in use for another user")
	ErrorInvalidEmail            = errors.New("invalid Email")
	ErrorInvalidID               = errors.New("invalid ID")
	ErrorNotFound                = errors.New("user not found in repository")
)

// RemoteIdentity represents a User's identity at an IDP.
type RemoteIdentity struct {
	// IDPCID is the identifier of the IDP which hosts this identity.
	ConnectorID string

	// ID is the identifier of this User at the IDP.
	ID string
}

func ValidEmail(email string) bool {
	address, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	if address.Name != "" || address.Address == "" {
		return false
	}
	return true
}

func ValidPassword(plaintext string) bool {
	return len(plaintext) > 5
}

// NewUserRepo returns an in-memory UserRepo useful for development.
func NewUserRepo() UserRepo {
	return &memUserRepo{
		usersByID:         make(map[string]User),
		userIDsByEmail:    make(map[string]string),
		userIDsByRemoteID: make(map[RemoteIdentity]string),
		remoteIDsByUserID: make(map[string]map[RemoteIdentity]struct{}),
	}
}

type memUserRepo struct {
	usersByID         map[string]User
	userIDsByEmail    map[string]string
	userIDsByRemoteID map[RemoteIdentity]string
	remoteIDsByUserID map[string]map[RemoteIdentity]struct{}
}

func (r *memUserRepo) Get(_ repo.Transaction, id string) (User, error) {
	user, ok := r.usersByID[id]
	if !ok {
		return User{}, ErrorNotFound
	}
	return user, nil
}

func (r *memUserRepo) GetByEmail(tx repo.Transaction, email string) (User, error) {
	userID, ok := r.userIDsByEmail[email]
	if !ok {
		return User{}, ErrorNotFound
	}
	return r.Get(tx, userID)
}

func (r *memUserRepo) Create(_ repo.Transaction, user User) error {
	if user.ID == "" {
		return ErrorInvalidID
	}

	if !ValidEmail(user.Email) {
		return ErrorInvalidEmail
	}

	// make sure no one has the same ID; if using UUID the chances of this
	// happening are astronomically small.
	_, ok := r.usersByID[user.ID]
	if ok {
		return ErrorDuplicateID
	}

	// make sure there's no other user with the same Email
	_, ok = r.userIDsByEmail[user.Email]
	if ok {
		return ErrorDuplicateEmail
	}

	r.set(user)
	return nil
}

func (r *memUserRepo) Update(_ repo.Transaction, user User) error {
	if user.ID == "" {
		return ErrorInvalidID
	}

	if !ValidEmail(user.Email) {
		return ErrorInvalidEmail
	}

	// make sure this user exists already
	_, ok := r.usersByID[user.ID]
	if !ok {
		return ErrorNotFound
	}

	// make sure there's no other user with the same Email
	otherID, ok := r.userIDsByEmail[user.Email]
	if ok && otherID != user.ID {
		return ErrorDuplicateEmail
	}

	r.set(user)
	return nil
}

func (r *memUserRepo) AddRemoteIdentity(_ repo.Transaction, userID string, ri RemoteIdentity) error {
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

func (r *memUserRepo) RemoveRemoteIdentity(_ repo.Transaction, userID string, ri RemoteIdentity) error {
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

func (r *memUserRepo) GetByRemoteIdentity(_ repo.Transaction, ri RemoteIdentity) (User, error) {
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

func (r *memUserRepo) GetRemoteIdentities(_ repo.Transaction, userID string) ([]RemoteIdentity, error) {
	ids := []RemoteIdentity{}
	for id := range r.remoteIDsByUserID[userID] {
		ids = append(ids, id)
	}
	return ids, nil
}

func (r *memUserRepo) GetAdminCount(_ repo.Transaction) (int, error) {
	var i int
	for _, usr := range r.usersByID {
		if usr.Admin {
			i++
		}
	}
	return i, nil
}

func (r *memUserRepo) set(user User) error {
	r.usersByID[user.ID] = user
	r.userIDsByEmail[user.Email] = user.ID
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
			memUserRepo.AddRemoteIdentity(nil, u.User.ID, ri)
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
		ID            string `json:"id"`
		DisplayName   string `json:"displayName"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"emailVerified"`
	}

	err := json.Unmarshal(data, &dec)
	if err != nil {
		return fmt.Errorf("invalid User entry: %v", err)
	}

	u.ID = dec.ID
	u.DisplayName = dec.DisplayName
	u.Email = dec.Email
	u.EmailVerified = dec.EmailVerified
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
