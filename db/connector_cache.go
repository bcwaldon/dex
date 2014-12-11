package db

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/coopernurse/gorp"
	"github.com/lib/pq"

	"github.com/coreos-inc/auth/pkg/log"
)

const (
	connectorCacheTableName = "connectorcache"
)

func newConnectorCacheModel(cID, key string, val interface{}, cr, exp time.Time) (*connectorCacheModel, error) {
	enc, err := json.Marshal(val)
	if err != nil {
		return nil, err
	}

	m := &connectorCacheModel{
		ConnectorID: cID,
		Key:         key,
		Value:       string(enc),
		CreatedAt:   cr,
		ExpiresAt:   exp,
	}

	return m, nil
}

type connectorCacheModel struct {
	ID          int       `db:"id"`
	ConnectorID string    `db:"connectorID"`
	Key         string    `db:"key"`
	Value       string    `db:"value"`
	CreatedAt   time.Time `db:"createdAt"`
	ExpiresAt   time.Time `db:"expiresAt"`
}

func (m *connectorCacheModel) Decode(val interface{}) error {
	return json.Unmarshal([]byte(m.Value), val)
}

func NewConnectorCache(dsn string) (*connectorCache, error) {
	dbm, err := dbMap(dsn)
	if err != nil {
		return nil, err
	}

	dbm.AddTableWithName(connectorCacheModel{}, connectorCacheTableName).SetKeys(true, "id")
	if err := dbm.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	r := &connectorCache{
		dbMap: dbm,
	}
	return r, nil
}

type connectorCache struct {
	dbMap *gorp.DbMap
}

func (r *connectorCache) Write(cID, key string, val interface{}, exp time.Time) error {
	m, err := newConnectorCacheModel(cID, key, val, time.Now().UTC(), exp)
	if err != nil {
		return err
	}

	return r.dbMap.Insert(m)
}

func (r *connectorCache) purge() error {
	qt := pq.QuoteIdentifier(connectorCacheTableName)
	q := fmt.Sprintf("DELETE FROM %s WHERE expiresAt < $1", qt)
	res, err := r.dbMap.Exec(q, time.Now().UTC())
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

	log.Infof("Deleted %s stale row(s) from %s table", d, connectorCacheTableName)
	return nil
}
