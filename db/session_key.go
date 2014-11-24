package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/session"
)

const (
	sessionKeyTableName = "sessionkey"
)

type sessionKeyModel struct {
	Key       string `db:"key"`
	SessionID string `db:"sessionID"`
}

func NewSessionKeyRepo(dsn string) (*SessionKeyRepo, error) {
	dbm, err := dbMap(dsn)
	if err != nil {
		return nil, err
	}

	dbm.AddTableWithName(sessionKeyModel{}, sessionKeyTableName).SetKeys(false, "key")
	if err := dbm.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	r := &SessionKeyRepo{
		dbMap: dbm,
	}
	return r, nil
}

type SessionKeyRepo struct {
	dbMap *gorp.DbMap
}

func (r *SessionKeyRepo) Push(sk session.SessionKey, exp time.Duration) error {
	skm := &sessionKeyModel{
		Key:       sk.Key,
		SessionID: sk.SessionID,
	}
	return r.dbMap.Insert(skm)
}

func (r *SessionKeyRepo) Pop(key string) (string, error) {
	m, err := r.dbMap.Get(sessionKeyModel{}, key)
	if err != nil {
		return "", err
	}

	skm, ok := m.(*sessionKeyModel)
	if !ok {
		return "", errors.New("unrecognized model")
	}

	n, err := r.dbMap.Delete(skm)
	if err != nil {
		return "", err
	} else if n != 1 {
		return "", fmt.Errorf("DELETE affected %d rows", n)
	}

	return skm.SessionID, nil
}

func (r *SessionKeyRepo) purge() error {
	return nil
}
