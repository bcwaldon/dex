package db

import (
	"errors"
	"net/url"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
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

func newClientIdentityModel(ci *oidc.ClientIdentity) *clientIdentityModel {
	return &clientIdentityModel{
		ID:          ci.Credentials.ID,
		Secret:      []byte(ci.Credentials.Secret),
		RedirectURL: ci.Metadata.RedirectURL.String(),
	}
}

type clientIdentityModel struct {
	ID          string `db:"id"`
	Secret      []byte `db:"secret"`
	RedirectURL string `db:"redirectURL"`
}

func (m *clientIdentityModel) ClientIdentity() (*oidc.ClientIdentity, error) {
	u, err := url.Parse(m.RedirectURL)
	if err != nil {
		return nil, err
	}

	ci := oidc.ClientIdentity{
		Credentials: oauth2.ClientCredentials{
			ID:     m.ID,
			Secret: string(m.Secret),
		},
		Metadata: oidc.ClientMetadata{
			RedirectURL: *u,
		},
	}

	return &ci, nil
}

func NewClientIdentityRepo(dbm *gorp.DbMap) *clientIdentityRepo {
	return &clientIdentityRepo{dbMap: dbm}
}

type clientIdentityRepo struct {
	dbMap *gorp.DbMap
}

func (r *clientIdentityRepo) Metadata(clientID string) (*oidc.ClientMetadata, error) {
	m, err := r.dbMap.Get(clientIdentityModel{}, clientID)
	if m == nil || err != nil {
		return nil, err
	}

	cim, ok := m.(*clientIdentityModel)
	if !ok {
		return nil, errors.New("unrecognized model")
	}

	ci, err := cim.ClientIdentity()
	if err != nil {
		return nil, err
	}

	return &ci.Metadata, nil
}

func (r *clientIdentityRepo) Authenticate(clientID, clientSecret string) (bool, error) {
	m, err := r.dbMap.Get(clientIdentityModel{}, clientID)
	if m == nil || err != nil {
		return false, err
	}

	cim, ok := m.(*clientIdentityModel)
	if !ok {
		return false, errors.New("unrecognized model")
	}

	if cim == nil || string(cim.Secret) != clientSecret {
		return false, nil
	}

	return true, nil
}

func (r *clientIdentityRepo) Create(ci oidc.ClientIdentity) error {
	return r.dbMap.Insert(newClientIdentityModel(&ci))
}
