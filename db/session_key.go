package db

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/coopernurse/gorp"
	"github.com/lib/pq"

	"github.com/coreos-inc/auth/session"
)

const (
	sessionKeyTableName = "sessionkey"
)

type sessionKeyModel struct {
	Key       string    `db:"key"`
	SessionID string    `db:"sessionID"`
	ExpiresAt time.Time `db:"expiresAt"`
	Stale     bool      `db:"stale"`
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
		ExpiresAt: time.Now().UTC().Add(exp),
		Stale:     false,
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

	if skm.Stale || skm.ExpiresAt.Before(time.Now().UTC()) {
		return "", errors.New("invalid session key")
	}

	qt := pq.QuoteIdentifier(sessionKeyTableName)
	q := fmt.Sprintf("UPDATE %s SET stale=$1 WHERE key=$2 AND stale=$3", qt)
	res, err := r.dbMap.Exec(q, true, key, false)
	if err != nil {
		return "", err
	}

	if n, err := res.RowsAffected(); n != 1 {
		if err != nil {
			log.Printf("Failed determining rows affected by UPDATE sessionKey query: %v", err)
		}
		return "", fmt.Errorf("failed to pop entity")
	}

	return skm.SessionID, nil
}

func (r *SessionKeyRepo) purge() error {
	qt := pq.QuoteIdentifier(sessionKeyTableName)
	q := fmt.Sprintf("DELETE FROM %s WHERE stale = $1 OR expiresAt < $2", qt)
	res, err := r.dbMap.Exec(q, true, time.Now().UTC())
	if err != nil {
		return err
	}

	d := "unknown # of"
	if n, err := res.RowsAffected(); err == nil {
		if n == 0 {
			return nil
		}
		d = fmt.Sprintf("%d", n)
	}

	log.Printf("Deleted %s stale row(s) from %s table", d, sessionKeyTableName)
	return nil
}
