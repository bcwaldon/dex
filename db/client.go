package db

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/coopernurse/gorp"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/coreos-inc/auth/oidc"
	pcrypto "github.com/coreos-inc/auth/pkg/crypto"
)

const (
	clientIdentityTableName = "clientidentity"

	bcryptHashCost = 10

	// Blowfish, the algorithm underlying bcrypt, has a maximum
	// password length of 72. We explicitly track and check this
	// since the bcrypt library will silently ignore portions of
	// a password past the first 72 characters.
	maxSecretLength = 72

	// postgres error codes
	pgErrorCodeUniqueViolation = "23505" // unique_violation
)

func init() {
	register(table{
		name:    clientIdentityTableName,
		model:   clientIdentityModel{},
		autoinc: false,
		pkey:    "id",
	})
}

func newClientIdentityModel(id string, secret []byte, meta *oidc.ClientMetadata) (*clientIdentityModel, error) {
	hashed, err := bcrypt.GenerateFromPassword(secret, bcryptHashCost)
	if err != nil {
		return nil, err
	}

	bmeta, err := json.Marshal(newClientMetadataJSON(meta))
	if err != nil {
		return nil, err
	}

	cim := clientIdentityModel{
		ID:       id,
		Secret:   hashed,
		Metadata: bmeta,
	}

	return &cim, nil
}

type clientIdentityModel struct {
	ID       string `db:"id"`
	Secret   []byte `db:"secret"`
	Metadata []byte `db:"metadata"`
}

func newClientMetadataJSON(cm *oidc.ClientMetadata) *clientMetadataJSON {
	cmj := clientMetadataJSON{
		RedirectURLs: make([]string, len(cm.RedirectURLs)),
	}

	for i, u := range cm.RedirectURLs {
		cmj.RedirectURLs[i] = (&u).String()
	}

	return &cmj
}

type clientMetadataJSON struct {
	RedirectURLs []string `json:"redirectURLs"`
}

func (cmj clientMetadataJSON) ClientMetadata() (*oidc.ClientMetadata, error) {
	cm := oidc.ClientMetadata{
		RedirectURLs: make([]url.URL, len(cmj.RedirectURLs)),
	}

	for i, us := range cmj.RedirectURLs {
		up, err := url.Parse(us)
		if err != nil {
			return nil, err
		}
		cm.RedirectURLs[i] = *up
	}

	return &cm, nil
}

func (m *clientIdentityModel) ClientIdentity() (*oidc.ClientIdentity, error) {
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID:     m.ID,
			Secret: string(m.Secret),
		},
	}

	var cmj clientMetadataJSON
	err := json.Unmarshal(m.Metadata, &cmj)
	if err != nil {
		return nil, err
	}

	cm, err := cmj.ClientMetadata()
	if err != nil {
		return nil, err
	}

	ci.Metadata = *cm
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

func (r *clientIdentityRepo) Authenticate(creds oidc.ClientCredentials) (bool, error) {
	m, err := r.dbMap.Get(clientIdentityModel{}, creds.ID)
	if m == nil || err != nil {
		return false, err
	}

	cim, ok := m.(*clientIdentityModel)
	if !ok {
		return false, errors.New("unrecognized model")
	}

	dec, err := base64.URLEncoding.DecodeString(creds.Secret)
	if err != nil {
		return false, nil
	}

	if len(dec) > maxSecretLength {
		return false, nil
	}

	ok = bcrypt.CompareHashAndPassword(cim.Secret, dec) == nil
	return ok, nil
}

func (r *clientIdentityRepo) New(id string, meta oidc.ClientMetadata) (*oidc.ClientCredentials, error) {
	secret, err := pcrypto.RandBytes(maxSecretLength)
	if err != nil {
		return nil, err
	}

	cim, err := newClientIdentityModel(id, secret, &meta)
	if err != nil {
		return nil, err
	}

	if err := r.dbMap.Insert(cim); err != nil {
		if perr, ok := err.(*pq.Error); ok && perr.Code == pgErrorCodeUniqueViolation {
			err = errors.New("client ID already exists")
		}

		return nil, err
	}

	cc := oidc.ClientCredentials{
		ID:     id,
		Secret: base64.URLEncoding.EncodeToString(secret),
	}

	return &cc, nil
}

func (r *clientIdentityRepo) All() ([]oidc.ClientIdentity, error) {
	qt := pq.QuoteIdentifier(clientIdentityTableName)
	q := fmt.Sprintf("SELECT * FROM %s", qt)
	objs, err := r.dbMap.Select(&clientIdentityModel{}, q)
	if err != nil {
		return nil, err
	}

	cs := make([]oidc.ClientIdentity, len(objs))
	for i, obj := range objs {
		m, ok := obj.(*clientIdentityModel)
		if !ok {
			return nil, errors.New("unable to cast client identity to clientIdentityModel")
		}

		ci, err := m.ClientIdentity()
		if err != nil {
			return nil, err
		}
		cs[i] = *ci
	}
	return cs, nil
}
