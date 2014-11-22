package session

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coopernurse/gorp"
	_ "github.com/lib/pq"

	"github.com/coreos-inc/auth/oidc"
)

const (
	sessionTableName    = "session"
	sessionKeyTableName = "sessionKey"
)

type sessionDBModel struct {
	ID          string    `db:"id"`
	State       string    `db:"state"`
	CreatedAt   time.Time `db:"createdAt"`
	ClientID    string    `db:"clientID"`
	ClientState string    `db:"clientState"`
	RedirectURL string    `db:"RedirectURL"`
	Identity    string    `db:"identity"`
}

func (s *sessionDBModel) Session() (*Session, error) {
	ru, err := url.Parse(s.RedirectURL)
	if err != nil {
		return nil, err
	}

	var ident oidc.Identity
	if err = json.Unmarshal([]byte(s.Identity), &ident); err != nil {
		return nil, err
	}

	ses := Session{
		ID:          s.ID,
		State:       SessionState(s.State),
		CreatedAt:   s.CreatedAt.UTC(),
		ClientID:    s.ClientID,
		ClientState: s.ClientState,
		RedirectURL: *ru,
		Identity:    ident,
	}

	return &ses, nil
}

func newSessionDBModel(s *Session) (*sessionDBModel, error) {
	ident, err := json.Marshal(s.Identity)
	if err != nil {
		return nil, err
	}

	sm := sessionDBModel{
		ID:          s.ID,
		State:       string(s.State),
		CreatedAt:   s.CreatedAt,
		ClientID:    s.ClientID,
		ClientState: s.ClientState,
		RedirectURL: s.RedirectURL.String(),
		Identity:    string(ident),
	}

	return &sm, nil
}

type sessionKeyDBModel struct {
	Key       string `db:"key"`
	SessionID string `db:"sessionID"`
}

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

func NewDBSessionRepo(dsn string) (*DBSessionRepo, error) {
	dbm, err := dbMap(dsn)
	if err != nil {
		return nil, err
	}

	dbm.AddTableWithName(sessionDBModel{}, sessionTableName).SetKeys(false, "id")
	if err := dbm.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	r := &DBSessionRepo{
		dbMap: dbm,
	}

	return r, nil
}

func NewDBSessionKeyRepo(dsn string) (*DBSessionKeyRepo, error) {
	dbm, err := dbMap(dsn)
	if err != nil {
		return nil, err
	}

	dbm.AddTableWithName(sessionKeyDBModel{}, sessionKeyTableName).SetKeys(false, "key")
	if err := dbm.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	r := &DBSessionKeyRepo{
		dbMap: dbm,
	}
	return r, nil
}

type DBSessionRepo struct {
	dbMap *gorp.DbMap
}

func (r *DBSessionRepo) Get(sessionID string) (*Session, error) {
	m, err := r.dbMap.Get(sessionDBModel{}, sessionID)
	if err != nil {
		return nil, err
	}

	sm, ok := m.(*sessionDBModel)
	if !ok {
		return nil, errors.New("unrecognized model")
	}

	return sm.Session()
}

func (r *DBSessionRepo) Create(s Session) error {
	sm, err := newSessionDBModel(&s)
	if err != nil {
		return err
	}
	return r.dbMap.Insert(sm)
}

func (r *DBSessionRepo) Update(s Session) error {
	sm, err := newSessionDBModel(&s)
	if err != nil {
		return err
	}
	n, err := r.dbMap.Update(sm)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("update affected unexpected number of rows")
	}
	return nil
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
