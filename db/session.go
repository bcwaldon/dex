package db

import (
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/session"
)

const (
	sessionTableName    = "session"
	sessionKeyTableName = "sessionKey"
)

type sessionModel struct {
	ID          string    `db:"id"`
	State       string    `db:"state"`
	CreatedAt   time.Time `db:"createdAt"`
	ClientID    string    `db:"clientID"`
	ClientState string    `db:"clientState"`
	RedirectURL string    `db:"RedirectURL"`
	Identity    []byte    `db:"identity"`
}

func (s *sessionModel) session() (*session.Session, error) {
	ru, err := url.Parse(s.RedirectURL)
	if err != nil {
		return nil, err
	}

	var ident oidc.Identity
	if err = json.Unmarshal(s.Identity, &ident); err != nil {
		return nil, err
	}

	ses := session.Session{
		ID:          s.ID,
		State:       session.SessionState(s.State),
		CreatedAt:   s.CreatedAt.UTC(),
		ClientID:    s.ClientID,
		ClientState: s.ClientState,
		RedirectURL: *ru,
		Identity:    ident,
	}

	return &ses, nil
}

func newSessionModel(s *session.Session) (*sessionModel, error) {
	b, err := json.Marshal(s.Identity)
	if err != nil {
		return nil, err
	}

	sm := sessionModel{
		ID:          s.ID,
		State:       string(s.State),
		CreatedAt:   s.CreatedAt,
		ClientID:    s.ClientID,
		ClientState: s.ClientState,
		RedirectURL: s.RedirectURL.String(),
		Identity:    b,
	}

	return &sm, nil
}

func NewSessionRepo(dsn string) (*SessionRepo, error) {
	dbm, err := dbMap(dsn)
	if err != nil {
		return nil, err
	}

	dbm.AddTableWithName(sessionModel{}, sessionTableName).SetKeys(false, "id")
	if err := dbm.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	r := &SessionRepo{
		dbMap: dbm,
	}

	return r, nil
}

type SessionRepo struct {
	dbMap *gorp.DbMap
}

func (r *SessionRepo) Get(sessionID string) (*session.Session, error) {
	m, err := r.dbMap.Get(sessionModel{}, sessionID)
	if err != nil {
		return nil, err
	}

	sm, ok := m.(*sessionModel)
	if !ok {
		return nil, errors.New("unrecognized model")
	}

	return sm.session()
}

func (r *SessionRepo) Create(s session.Session) error {
	sm, err := newSessionModel(&s)
	if err != nil {
		return err
	}
	return r.dbMap.Insert(sm)
}

func (r *SessionRepo) Update(s session.Session) error {
	sm, err := newSessionModel(&s)
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

func (r *SessionRepo) purge() error {
	return nil
}
