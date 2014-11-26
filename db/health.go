package db

import (
	"fmt"

	"github.com/coopernurse/gorp"
)

func NewHealthChecker(dsn string) (*healthChecker, error) {
	dbm, err := dbMap(dsn)
	if err != nil {
		return nil, err
	}

	return &healthChecker{dbMap: dbm}, nil
}

type healthChecker struct {
	dbMap *gorp.DbMap
}

func (hc *healthChecker) Healthy() (err error) {
	if err = hc.dbMap.Db.Ping(); err != nil {
		err = fmt.Errorf("database error: %v", err)
	}
	return
}
