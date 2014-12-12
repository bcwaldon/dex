package db

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/coopernurse/gorp"
	_ "github.com/lib/pq"
)

type table struct {
	name    string
	model   interface{}
	autoinc bool
	pkey    string
}

var (
	tables []table
)

func register(t table) {
	tables = append(tables, t)
}

func NewConnection(dsn string) (*gorp.DbMap, error) {
	if !strings.HasPrefix(dsn, "postgres://") {
		return nil, errors.New("unrecognized database driver")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	dbm := gorp.DbMap{
		Db:      db,
		Dialect: gorp.PostgresDialect{},
	}

	for _, t := range tables {
		dbm.AddTableWithName(t.model, t.name).SetKeys(t.autoinc, t.pkey)
	}

	if err := dbm.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	return &dbm, nil
}
