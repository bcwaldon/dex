package db

import (
	"errors"
	"net/url"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/oauth2"
)

const (
	clientIdentityTableName = "clientidentity"
)

func init() {
	register(table{
		name:    clientIdentityTableName,
		model:   clientIdentityModel{},
		autoinc: false,
		pkey:    "id",
	})
}

func newClientIdentityModel(ci *oauth2.ClientIdentity) *clientIdentityModel {
	return &clientIdentityModel{
		ID:          ci.ID,
		Secret:      []byte(ci.Secret),
		RedirectURL: ci.RedirectURL.String(),
	}
}

type clientIdentityModel struct {
	ID          string `db:"id"`
	Secret      []byte `db:"secret"`
	RedirectURL string `db:"redirectURL"`
}

func (m *clientIdentityModel) ClientIdentity() (*oauth2.ClientIdentity, error) {
	u, err := url.Parse(m.RedirectURL)
	if err != nil {
		return nil, err
	}

	ci := oauth2.ClientIdentity{
		ID:          m.ID,
		Secret:      string(m.Secret),
		RedirectURL: *u,
	}

	return &ci, nil
}

func NewClientIdentityRepo(dbm *gorp.DbMap) *clientIdentityRepo {
	return &clientIdentityRepo{dbMap: dbm}
}

type clientIdentityRepo struct {
	dbMap *gorp.DbMap
}

func (r *clientIdentityRepo) Find(clientID string) (*oauth2.ClientIdentity, error) {
	m, err := r.dbMap.Get(clientIdentityModel{}, clientID)
	if m == nil || err != nil {
		return nil, err
	}

	cim, ok := m.(*clientIdentityModel)
	if !ok {
		return nil, errors.New("unrecognized model")
	}

	return cim.ClientIdentity()
}

func (cr *clientIdentityRepo) Authenticate(clientID, clientSecret string) (bool, error) {
	ci, err := cr.Find(clientID)
	if err != nil {
		return false, err
	}
	if ci == nil || ci.Secret != clientSecret {
		return false, nil
	}
	return true, nil
}

func (r *clientIdentityRepo) Create(ci oauth2.ClientIdentity) error {
	return r.dbMap.Insert(newClientIdentityModel(&ci))
}
