package db

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/coopernurse/gorp"
	_ "github.com/lib/pq"
)

func dbMap(dsn string) (*gorp.DbMap, error) {
	if !strings.HasPrefix(dsn, "postgres://") {
		return nil, errors.New("unrecognized database driver")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	dbmap := gorp.DbMap{
		Db:      db,
		Dialect: gorp.PostgresDialect{},
	}

	return &dbmap, nil
}
