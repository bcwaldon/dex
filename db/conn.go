package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/coopernurse/gorp"
	_ "github.com/lib/pq"
)

var (
	dbCache = map[string]*sql.DB{}
)

func dbMap(dsn string) (*gorp.DbMap, error) {
	if !strings.HasPrefix(dsn, "postgres://") {
		return nil, errors.New("unrecognized database driver")
	}

	db, ok := dbCache[dsn]
	if !ok {
		var err error
		db, err = sql.Open("postgres", dsn)
		if err != nil {
			return nil, err
		}
		dbCache[dsn] = db
	}

	dbmap := gorp.DbMap{
		Db:      db,
		Dialect: gorp.PostgresDialect{},
	}

	return &dbmap, nil
}
