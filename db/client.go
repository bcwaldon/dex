package db

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/coopernurse/gorp"
	"golang.org/x/crypto/bcrypt"

	"github.com/coreos-inc/auth/oidc"
)

const (
	clientIdentityTableName = "clientidentity"

	bcryptHashCost = 10

	// Blowfish, the algorithm underlying bcrypt, has a maximum
	// password length of 72. We explicitly track and check this
	// since the bcrypt library will silently ignore portions of
	// a password past the first 72 characters.
	maxSecretLength = 72
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

	cim := clientIdentityModel{
		ID:          id,
		Secret:      hashed,
		RedirectURL: meta.RedirectURL.String(),
	}

	return &cim, nil
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
		Credentials: oidc.ClientCredentials{
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

func (r *clientIdentityRepo) New(meta oidc.ClientMetadata) (*oidc.ClientCredentials, error) {
	id, err := genClientID(meta.RedirectURL.Host)
	if err != nil {
		return nil, err
	}

	secret, err := randBytes(maxSecretLength)
	if err != nil {
		return nil, err
	}

	cim, err := newClientIdentityModel(id, secret, &meta)
	if err != nil {
		return nil, err
	}

	if err := r.dbMap.Insert(cim); err != nil {
		return nil, err
	}

	cc := oidc.ClientCredentials{
		ID:     id,
		Secret: base64.URLEncoding.EncodeToString(secret),
	}

	return &cc, nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	got, err := rand.Read(b)
	if err != nil {
		return nil, err
	} else if n != got {
		return nil, errors.New("unable to generate enough random data")
	}
	return b, nil
}

func genClientID(hostport string) (string, error) {
	b, err := randBytes(32)
	if err != nil {
		return "", err
	}

	var host string
	if strings.Contains(hostport, ":") {
		host, _, err = net.SplitHostPort(hostport)
		if err != nil {
			return "", err
		}
	} else {
		host = hostport
	}

	return fmt.Sprintf("%s@%s", base64.URLEncoding.EncodeToString(b), host), nil
}
