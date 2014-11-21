package session

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	sessionKeyTableName = "sessionKey"
)

func NewDBSessionKeyRepo(dsn string) (*DBSessionKeyRepo, error) {
	if !strings.HasPrefix(dsn, "postgres://") {
		return nil, errors.New("unrecognized database driver")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	r := &DBSessionKeyRepo{
		db:        db,
		TableName: sessionKeyTableName,
	}
	return r, nil
}

type DBSessionKeyRepo struct {
	TableName string
	db        *sql.DB
}

func (r *DBSessionKeyRepo) Push(sk SessionKey, exp time.Duration) error {
	q := fmt.Sprintf("INSERT INTO %s (key, sessionID) VALUES ($1, $2)", pq.QuoteIdentifier(r.TableName))
	_, err := r.db.Query(q, sk.Key, sk.SessionID)
	return err
}

func (r *DBSessionKeyRepo) Pop(key string) (string, error) {
	var sessionID string
	q := fmt.Sprintf("SELECT sessionID FROM %s WHERE key=$1", pq.QuoteIdentifier(r.TableName))
	err := r.db.QueryRow(q, key).Scan(&sessionID)
	if err != nil {
		return "", err
	}

	q = fmt.Sprintf("DELETE FROM %s WHERE key=$1", pq.QuoteIdentifier(r.TableName))
	res, err := r.db.Exec(q, key)
	if err != nil {
		return "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", err
	} else if n != 1 {
		return "", fmt.Errorf("DELETE affected %d rows", n)
	}

	return sessionID, nil
}

func (r *DBSessionKeyRepo) Init() error {
	q := fmt.Sprintf("CREATE TABLE %s (key VARCHAR, sessionID VARCHAR)", pq.QuoteIdentifier(r.TableName))
	_, err := r.db.Query(q)
	return err
}
