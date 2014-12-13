package db

import (
	"fmt"

	"github.com/coopernurse/gorp"
)

func NewHealthChecker(dbm *gorp.DbMap) *healthChecker {
	return &healthChecker{dbMap: dbm}
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
