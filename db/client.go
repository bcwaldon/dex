package db

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"

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

func newClientIdentityModel(id string, secret []byte, meta *oidc.ClientMetadata) *clientIdentityModel {
	return &clientIdentityModel{
		ID:          id,
		Secret:      secret,
		RedirectURL: meta.RedirectURL.String(),
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
	dec, err := base64.URLEncoding.DecodeString(clientSecret)
	if err != nil {
		return false, err
	}

	m, err := r.dbMap.Get(clientIdentityModel{}, clientID)
	if m == nil || err != nil {
		return false, err
	}

	cim, ok := m.(*clientIdentityModel)
	if !ok {
		return false, errors.New("unrecognized model")
	}

	if cim == nil || !reflect.DeepEqual(cim.Secret, dec) {
		return false, nil
	}

	return true, nil
}

func (r *clientIdentityRepo) New(meta oidc.ClientMetadata) (*oauth2.ClientCredentials, error) {
	id, err := genClientID(meta.RedirectURL.Host)
	if err != nil {
		return nil, err
	}

	secret, err := randBytes(128)
	if err != nil {
		return nil, err
	}

	cim := newClientIdentityModel(id, secret, &meta)
	if err := r.dbMap.Insert(cim); err != nil {
		return nil, err
	}

	cc := oauth2.ClientCredentials{
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
