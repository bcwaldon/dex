package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/coopernurse/gorp"
	_ "github.com/lib/pq"

	"github.com/coreos-inc/auth/pkg/log"
	ptime "github.com/coreos-inc/auth/pkg/time"
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

func Tables() []string {
	tn := make([]string, 0, len(tables))
	for _, t := range tables {
		tn = append(tn, t.name)
	}
	return tn
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

	var sleep time.Duration
	for {
		if err = dbm.CreateTablesIfNotExists(); err == nil {
			break
		}
		sleep = ptime.ExpBackoff(sleep, time.Minute)
		log.Errorf("Unable to initialize database, retrying in %v: %v", sleep, err)
		time.Sleep(sleep)
	}

	return &dbm, nil
}
