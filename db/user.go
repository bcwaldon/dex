package db

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/user"
)

const (
	userTableName                  = "authduser"
	remoteIdentityMappingTableName = "remoteidentitymapping"
)

func init() {
	register(table{
		name:    userTableName,
		model:   userModel{},
		autoinc: false,
		pkey:    []string{"id"},
	})

	register(table{
		name:    remoteIdentityMappingTableName,
		model:   remoteIdentityMappingModel{},
		autoinc: false,
		pkey:    []string{"connectorID", "remoteID"},
	})
}

func NewUserRepo(dbm *gorp.DbMap) user.UserRepo {
	return &userRepo{
		dbMap:           dbm,
		userIDGenerator: user.DefaultUserIDGenerator,
	}
}

func NewUserRepoFromUsers(dbm *gorp.DbMap, us []user.UserWithRemoteIdentities) (user.UserRepo, error) {
	repo := NewUserRepo(dbm).(*userRepo)
	for _, u := range us {
		um, err := newUserModel(&u.User)
		if err != nil {
			return nil, err
		}
		err = repo.dbMap.Insert(um)
		for _, ri := range u.RemoteIdentities {
			err = repo.AddRemoteIdentity(u.User.ID, ri)
			if err != nil {
				return nil, err
			}
		}
	}
	return repo, nil
}

type userRepo struct {
	dbMap           *gorp.DbMap
	userIDGenerator user.UserIDGenerator
}

func (r *userRepo) Get(userID string) (user.User, error) {
	return r.get(nil, userID)
}

func (r *userRepo) GetByEmail(email string) (user.User, error) {
	return r.getByEmail(nil, email)
}

func (r *userRepo) Create(usr user.User) (userID string, err error) {
	if usr.ID != "" {
		return "", user.ErrorInvalidID
	}

	newID, err := r.userIDGenerator()
	if err != nil {
		return "", err
	}

	tx, err := r.dbMap.Begin()
	if err != nil {
		return "", err
	}

	_, err = r.get(tx, userID)
	if err != nil {
		if err != user.ErrorNotFound {
			rollback(tx)
			return "", err
		}
	} else {
		rollback(tx)
		return "", user.ErrorDuplicateID
	}

	// make sure there's no other user with the same Email
	_, err = r.getByEmail(tx, usr.Email)
	if err != nil {
		if err != user.ErrorNotFound {
			rollback(tx)
			return "", err
		}
	} else {
		rollback(tx)
		return "", user.ErrorDuplicateEmail
	}

	usr.ID = newID
	err = r.insert(tx, usr)
	if err != nil {
		rollback(tx)
		return "", err
	}

	err = tx.Commit()
	if err != nil {
		rollback(tx)
		return "", fmt.Errorf("error inserting user: %v", err)
	}
	return newID, nil
}

func (r *userRepo) Update(usr user.User) error {
	if usr.ID == "" {
		return user.ErrorInvalidID
	}

	tx, err := r.dbMap.Begin()
	if err != nil {
		return err
	}

	if !user.ValidEmail(usr.Email) {
		return user.ErrorInvalidEmail
	}

	// make sure this user exists already
	_, err = r.get(tx, usr.ID)
	if err != nil {
		rollback(tx)
		return err
	}

	// make sure there's no other user with the same Email
	otherUser, err := r.getByEmail(tx, usr.Email)
	if err != user.ErrorNotFound {
		if err != nil {
			rollback(tx)
			return err
		}
		if otherUser.ID != usr.ID {
			rollback(tx)
			return user.ErrorDuplicateEmail
		}
	}

	err = r.update(tx, usr)
	if err != nil {
		rollback(tx)
		return err
	}

	err = tx.Commit()
	if err != nil {
		rollback(tx)
		return err
	}
	return nil
}

func (r *userRepo) GetByRemoteIdentity(ri user.RemoteIdentity) (user.User, error) {
	tx, err := r.dbMap.Begin()
	if err != nil {
		return user.User{}, err
	}

	userID, err := r.getUserIDForRemoteIdentity(tx, ri)
	if err != nil {
		rollback(tx)
		return user.User{}, err
	}

	usr, err := r.get(tx, userID)
	if err != nil {
		rollback(tx)
		return user.User{}, err
	}

	err = tx.Commit()
	if err != nil {
		rollback(tx)
		return user.User{}, err
	}

	return usr, nil
}

func (r *userRepo) AddRemoteIdentity(userID string, ri user.RemoteIdentity) error {
	tx, err := r.dbMap.Begin()
	if err != nil {
		return err
	}

	_, err = r.get(tx, userID)
	if err != nil {
		rollback(tx)
		return err
	}

	otherUserID, err := r.getUserIDForRemoteIdentity(tx, ri)
	if err != user.ErrorNotFound {
		if err == nil && otherUserID != "" {
			rollback(tx)
			return user.ErrorDuplicateRemoteIdentity
		}
		rollback(tx)
		return err
	}

	err = r.insertRemoteIdentity(tx, userID, ri)
	if err != nil {
		rollback(tx)
		return err
	}

	err = tx.Commit()
	if err != nil {
		rollback(tx)
		return err
	}

	return nil
}

func (r *userRepo) RemoveRemoteIdentity(userID string, rid user.RemoteIdentity) error {
	if userID == "" || rid.ID == "" || rid.ConnectorID == "" {
		return user.ErrorInvalidID
	}

	tx, err := r.dbMap.Begin()
	if err != nil {
		return err
	}

	otherUserID, err := r.getUserIDForRemoteIdentity(tx, rid)
	if err != nil {
		rollback(tx)
		return err
	}
	if otherUserID != userID {
		rollback(tx)
		return user.ErrorNotFound
	}

	rim, err := newRemoteIdentityMappingModel(userID, rid)
	if err != nil {
		rollback(tx)
		return err
	}

	deleted, err := tx.Delete(rim)

	if err != nil {
		rollback(tx)
		return err
	}

	if deleted == 0 {
		rollback(tx)
		return user.ErrorNotFound
	}

	err = tx.Commit()
	if err != nil {
		rollback(tx)
		return err
	}
	return nil
}

func (r *userRepo) GetRemoteIdentities(userID string) ([]user.RemoteIdentity, error) {
	if userID == "" {
		return nil, user.ErrorInvalidID
	}

	rims, err := r.dbMap.Select(&remoteIdentityMappingModel{},
		"select * from remoteidentitymapping where userID = $1", userID)

	if err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
		return nil, err
	}
	if len(rims) == 0 {
		return nil, nil
	}

	var ris []user.RemoteIdentity
	for _, m := range rims {
		rim, ok := m.(*remoteIdentityMappingModel)
		if !ok {
			return nil, errors.New("unrecognized model")
		}

		ris = append(ris, user.RemoteIdentity{
			ID:          rim.RemoteID,
			ConnectorID: rim.ConnectorID,
		})
	}

	return ris, nil
}

func (r *userRepo) GetAdminCount() (int, error) {
	i, err := r.dbMap.SelectInt(fmt.Sprintf("SELECT count(*) FROM %s where admin=true", userTableName))
	return int(i), err
}

func (r *userRepo) executor(tx *gorp.Transaction) gorp.SqlExecutor {
	if tx == nil {
		return r.dbMap
	}
	return tx
}

func (r *userRepo) insert(tx *gorp.Transaction, usr user.User) error {
	ex := r.executor(tx)
	um, err := newUserModel(&usr)
	if err != nil {
		return err
	}
	return ex.Insert(um)
}

func (r *userRepo) update(tx *gorp.Transaction, usr user.User) error {
	ex := r.executor(tx)
	um, err := newUserModel(&usr)
	if err != nil {
		return err
	}
	_, err = ex.Update(um)
	return err
}

func (r *userRepo) get(tx *gorp.Transaction, userID string) (user.User, error) {
	ex := r.executor(tx)

	m, err := ex.Get(userModel{}, userID)
	if err != nil {
		return user.User{}, err
	}

	if m == nil {
		return user.User{}, user.ErrorNotFound
	}

	um, ok := m.(*userModel)
	if !ok {
		return user.User{}, errors.New("unrecognized model")
	}

	return um.user()
}

func (r *userRepo) getUserIDForRemoteIdentity(tx *gorp.Transaction, ri user.RemoteIdentity) (string, error) {
	ex := r.executor(tx)

	m, err := ex.Get(remoteIdentityMappingModel{}, ri.ConnectorID, ri.ID)
	if err != nil {
		return "", err
	}

	if m == nil {
		return "", user.ErrorNotFound
	}

	rim, ok := m.(*remoteIdentityMappingModel)
	if !ok {
		return "", errors.New("unrecognized model")
	}

	return rim.UserID, nil
}

func (r *userRepo) getByEmail(tx *gorp.Transaction, email string) (user.User, error) {
	ex := r.executor(tx)
	var um userModel
	err := ex.SelectOne(&um, "select * from authduser where email = $1", email)

	if err != nil {
		if err == sql.ErrNoRows {
			return user.User{}, user.ErrorNotFound
		}
		return user.User{}, err
	}
	return um.user()
}

func (r *userRepo) insertRemoteIdentity(tx *gorp.Transaction, userID string, ri user.RemoteIdentity) error {
	ex := r.executor(tx)
	rim, err := newRemoteIdentityMappingModel(userID, ri)
	if err != nil {

		return err
	}
	err = ex.Insert(rim)
	return err
}

type userModel struct {
	ID            string `db:"id"`
	Email         string `db:"email"`
	EmailVerified bool   `db:"emailVerified"`
	DisplayName   string `db:"displayName"`
	Admin         bool   `db:"admin"`
}

func (u *userModel) user() (user.User, error) {
	usr := user.User{
		ID:            u.ID,
		DisplayName:   u.DisplayName,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Admin:         u.Admin,
	}

	return usr, nil
}

func newUserModel(u *user.User) (*userModel, error) {
	um := userModel{
		ID:            u.ID,
		DisplayName:   u.DisplayName,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Admin:         u.Admin,
	}

	return &um, nil
}

func newRemoteIdentityMappingModel(userID string, ri user.RemoteIdentity) (*remoteIdentityMappingModel, error) {
	return &remoteIdentityMappingModel{
		ConnectorID: ri.ConnectorID,
		UserID:      userID,
		RemoteID:    ri.ID,
	}, nil
}

type remoteIdentityMappingModel struct {
	ConnectorID string `db:"connectorID"`
	UserID      string `db:"userID"`
	RemoteID    string `db:"remoteID"`
}
