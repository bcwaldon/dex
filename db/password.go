package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/user"
)

const (
	passwordInfoTableName = "passwordinfo"
)

func init() {
	register(table{
		name:    passwordInfoTableName,
		model:   passwordInfoModel{},
		autoinc: false,
		pkey:    []string{"userId"},
	})

}

type passwordInfoModel struct {
	UserID          string `db:"userId"`
	PasswordHash    []byte `db:"passwordHash"`
	PasswordExpires int64  `db:"passwordExpires"`
}

func NewPasswordInfoRepo(dbm *gorp.DbMap) user.PasswordInfoRepo {
	return &passwordInfoRepo{
		dbMap: dbm,
	}
}

type passwordInfoRepo struct {
	dbMap *gorp.DbMap
}

func (r *passwordInfoRepo) Get(userID string) (user.PasswordInfo, error) {
	return r.get(nil, userID)
}

func (r *passwordInfoRepo) Create(pw user.PasswordInfo) (err error) {
	if pw.UserID == "" {
		return user.ErrorInvalidID
	}

	tx, err := r.dbMap.Begin()
	if err != nil {
		return err
	}

	_, err = r.get(tx, pw.UserID)
	if err != nil {
		if err != user.ErrorNotFound {
			rollback(tx)
			return err
		}
	} else {
		rollback(tx)
		return user.ErrorDuplicateID
	}

	err = r.insert(tx, pw)
	if err != nil {
		rollback(tx)
		return err
	}

	err = tx.Commit()
	if err != nil {
		rollback(tx)
		return fmt.Errorf("error inserting PasswordInfo: %v", err)
	}
	return nil
}

func (r *passwordInfoRepo) Update(pw user.PasswordInfo) error {
	if pw.UserID == "" {
		return user.ErrorInvalidID
	}

	if len(pw.Password) == 0 {
		return user.ErrorInvalidPassword
	}

	tx, err := r.dbMap.Begin()
	if err != nil {
		return err
	}

	// make sure this user exists already
	_, err = r.get(tx, pw.UserID)
	if err != nil {
		rollback(tx)
		return err
	}

	err = r.update(tx, pw)
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

func (r *passwordInfoRepo) executor(tx *gorp.Transaction) gorp.SqlExecutor {
	if tx == nil {
		return r.dbMap
	}
	return tx
}

func (r *passwordInfoRepo) get(tx *gorp.Transaction, id string) (user.PasswordInfo, error) {
	ex := r.executor(tx)

	m, err := ex.Get(passwordInfoModel{}, id)
	if err != nil {
		return user.PasswordInfo{}, nil
	}

	if m == nil {
		return user.PasswordInfo{}, user.ErrorNotFound
	}

	pwm, ok := m.(*passwordInfoModel)
	if !ok {
		return user.PasswordInfo{}, errors.New("unrecognized model")
	}

	return pwm.passwordInfo()
}

func (r *passwordInfoRepo) insert(tx *gorp.Transaction, pw user.PasswordInfo) error {
	ex := r.executor(tx)
	pm, err := newPasswordInfoModel(&pw)
	if err != nil {
		return err
	}
	return ex.Insert(pm)
}

func (r *passwordInfoRepo) update(tx *gorp.Transaction, pw user.PasswordInfo) error {
	ex := r.executor(tx)
	pm, err := newPasswordInfoModel(&pw)
	if err != nil {
		return err
	}
	_, err = ex.Update(pm)
	return err
}

func (p *passwordInfoModel) passwordInfo() (user.PasswordInfo, error) {
	pw := user.PasswordInfo{
		UserID:   p.UserID,
		Password: p.PasswordHash,
	}

	if p.PasswordExpires != 0 {
		pw.PasswordExpires = time.Unix(p.PasswordExpires, 0).UTC()
	}

	return pw, nil
}

func newPasswordInfoModel(p *user.PasswordInfo) (*passwordInfoModel, error) {
	pw := passwordInfoModel{
		UserID:       p.UserID,
		PasswordHash: []byte(p.Password),
	}

	if !p.PasswordExpires.IsZero() {
		pw.PasswordExpires = p.PasswordExpires.Unix()
	}

	return &pw, nil
}
