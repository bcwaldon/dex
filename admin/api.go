// package admin provides an implementation of the API described in auth/schema/adminschema.
package admin

import (
	"net/http"

	"github.com/coreos-inc/auth/schema/adminschema"
	"github.com/coreos-inc/auth/user"
)

// AdminAPI provides the logic necessary to implement the Admin API.
type AdminAPI struct {
	userRepo         user.UserRepo
	passwordInfoRepo user.PasswordInfoRepo
	localConnectorID string
}

func NewAdminAPI(userRepo user.UserRepo, pwiRepo user.PasswordInfoRepo, localConnectorID string) *AdminAPI {
	if localConnectorID == "" {
		panic("must specify non-blank localConnectorID")
	}

	return &AdminAPI{
		userRepo:         userRepo,
		passwordInfoRepo: pwiRepo,
		localConnectorID: localConnectorID,
	}
}

// Error is the error type returned by AdminAPI methods.
type Error struct {
	Type string

	// The HTTP Code to return for this type of error.
	Code int

	Desc string

	// The underlying error - not to be consumed by external users.
	Internal error
}

func (e Error) Error() string {
	return e.Type
}

func errorMaker(typ string, desc string, code int) func(internal error) Error {
	return func(internal error) Error {
		return Error{
			Type:     typ,
			Code:     code,
			Desc:     desc,
			Internal: internal,
		}
	}
}

var (
	errorMap = map[error]func(error) Error{
		user.ErrorNotFound:       errorMaker("resource_not_found", "Resource could not be found.", http.StatusNotFound),
		user.ErrorDuplicateEmail: errorMaker("bad_request", "Email already in use.", http.StatusBadRequest),
		user.ErrorInvalidEmail:   errorMaker("bad_request", "invalid email.", http.StatusBadRequest),
	}
)

func (a *AdminAPI) GetAdmin(id string) (adminschema.Admin, error) {
	usr, err := a.userRepo.Get(id)

	if err != nil {
		return adminschema.Admin{}, mapError(err)
	}

	pwi, err := a.passwordInfoRepo.Get(id)
	if err != nil {
		return adminschema.Admin{}, mapError(err)
	}

	return adminschema.Admin{
		Id:       id,
		Email:    usr.Email,
		Password: string(pwi.Password),
	}, nil
}

func (a *AdminAPI) CreateAdmin(admn adminschema.Admin) (string, error) {
	usr := user.User{}
	usr.Email = admn.Email
	usr.Admin = true

	id, err := a.userRepo.Create(usr)
	if err != nil {
		return "", mapError(err)
	}

	err = a.userRepo.AddRemoteIdentity(id, user.RemoteIdentity{
		ConnectorID: a.localConnectorID,
		ID:          id,
	})
	if err != nil {
		return "", mapError(err)
	}

	pwi := user.PasswordInfo{
		UserID:   id,
		Password: user.Password(admn.Password),
	}

	// TODO(bobbyrullo): This is racy and difficult to recover from since we're not using transactions.
	err = a.passwordInfoRepo.Create(pwi)
	if err != nil {
		return "", mapError(err)
	}

	return id, nil
}

func (a *AdminAPI) GetState() (adminschema.State, error) {
	state := adminschema.State{}

	admins, err := a.userRepo.GetAdminCount()
	if err != nil {
		return adminschema.State{}, err
	}

	state.AdminUserCreated = admins > 0

	return state, nil
}

func mapError(e error) error {
	if mapped, ok := errorMap[e]; ok {
		return mapped(e)
	}
	return Error{
		Code:     http.StatusInternalServerError,
		Type:     "server_error",
		Desc:     "",
		Internal: e,
	}
}