package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/coopernurse/gorp"
	"github.com/lib/pq"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos-inc/auth/session"
)

const (
	sessionTableName = "session"
)

func init() {
	register(table{
		name:    sessionTableName,
		model:   sessionModel{},
		autoinc: false,
		pkey:    "id",
	})
}

type sessionModel struct {
	ID          string    `db:"id"`
	State       string    `db:"state"`
	CreatedAt   time.Time `db:"createdAt"`
	ExpiresAt   time.Time `db:"expiresAt"`
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
		ExpiresAt:   s.ExpiresAt.UTC(),
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
		ExpiresAt:   s.ExpiresAt,
		ClientID:    s.ClientID,
		ClientState: s.ClientState,
		RedirectURL: s.RedirectURL.String(),
		Identity:    b,
	}

	return &sm, nil
}

func NewSessionRepo(dbm *gorp.DbMap) *SessionRepo {
	return &SessionRepo{dbMap: dbm}
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

	if sm.ExpiresAt.Before(time.Now().UTC()) {
		return nil, errors.New("session does not exist")
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
	qt := pq.QuoteIdentifier(sessionTableName)
	q := fmt.Sprintf("DELETE FROM %s WHERE expiresAt < $1 OR state = $2", qt)
	res, err := r.dbMap.Exec(q, time.Now().UTC(), string(session.SessionStateDead))
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

	log.Infof("Deleted %s stale row(s) from %s table", d, sessionTableName)
	return nil
}
