package session

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coopernurse/gorp"
	_ "github.com/lib/pq"
)

const (
	sessionKeyTableName = "sessionKey"
)

type sessionKeyDBModel struct {
	Key       string `db:"key"`
	SessionID string `db:"sessionID"`
}

func NewDBSessionKeyRepo(dsn string) (*DBSessionKeyRepo, error) {
	if !strings.HasPrefix(dsn, "postgres://") {
		return nil, errors.New("unrecognized database driver")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	dbMap := &gorp.DbMap{
		Db:      db,
		Dialect: gorp.PostgresDialect{},
	}

	dbMap.AddTableWithName(sessionKeyDBModel{}, sessionKeyTableName).SetKeys(false, "key")

	if err := dbMap.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	r := &DBSessionKeyRepo{
		dbMap: dbMap,
	}
	return r, nil
}

type DBSessionKeyRepo struct {
	dbMap *gorp.DbMap
}

func (r *DBSessionKeyRepo) Push(sk SessionKey, exp time.Duration) error {
	skm := &sessionKeyDBModel{
		Key:       sk.Key,
		SessionID: sk.SessionID,
	}
	return r.dbMap.Insert(skm)
}

func (r *DBSessionKeyRepo) Pop(key string) (string, error) {
	m, err := r.dbMap.Get(sessionKeyDBModel{}, key)
	if err != nil {
		return "", err
	}

	skm, ok := m.(*sessionKeyDBModel)
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
