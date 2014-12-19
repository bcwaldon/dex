package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
	pcrypto "github.com/coreos-inc/auth/pkg/crypto"
)

type ClientIdentityRepo interface {
	// Metadata returns one matching ClientMetadata if the given client
	// exists, otherwise nil. The returned error will be non-nil only
	// if the repo was unable to determine client existence.
	Metadata(clientID string) (*oidc.ClientMetadata, error)

	// Authenticate asserts that a client with the given ID exists and
	// that the provided secret matches. If either of these assertions
	// fail, (false, nil) will be returned. Only if the repo is unable
	// to make these assertions will a non-nil error be returned.
	Authenticate(creds oidc.ClientCredentials) (bool, error)

	// New registers a new ClientIdentity with the repo for the given metadata.
	// A unique Client ID and Secret will be generated and returned.
	New(meta oidc.ClientMetadata) (*oidc.ClientCredentials, error)
}

func NewClientIdentityRepo(cs []oidc.ClientIdentity) ClientIdentityRepo {
	cr := memClientIdentityRepo{
		idents: make(map[string]oidc.ClientIdentity, len(cs)),
	}

	for _, c := range cs {
		c := c
		cr.idents[c.Credentials.ID] = c
	}

	return &cr
}

type memClientIdentityRepo struct {
	idents map[string]oidc.ClientIdentity
}

func (cr *memClientIdentityRepo) New(meta oidc.ClientMetadata) (*oidc.ClientCredentials, error) {
	id, err := oidc.GenClientID(meta.RedirectURL.Host)
	if err != nil {
		return nil, err
	}

	secret, err := pcrypto.RandBytes(32)
	if err != nil {
		return nil, err
	}

	cc := oidc.ClientCredentials{
		ID:     id,
		Secret: base64.URLEncoding.EncodeToString(secret),
	}

	cr.idents[id] = oidc.ClientIdentity{
		Metadata:    meta,
		Credentials: cc,
	}

	return &cc, nil
}

func (cr *memClientIdentityRepo) Metadata(clientID string) (*oidc.ClientMetadata, error) {
	ci, ok := cr.idents[clientID]
	if !ok {
		return nil, nil
	}
	return &ci.Metadata, nil
}

func (cr *memClientIdentityRepo) Authenticate(creds oidc.ClientCredentials) (bool, error) {
	ci, ok := cr.idents[creds.ID]
	ok = ok && ci.Credentials.Secret == creds.Secret
	return ok, nil
}

func newClientIdentityRepoFromReader(r io.Reader) (ClientIdentityRepo, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var cs []clientIdentity
	if err = json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}

	ocs := make([]oidc.ClientIdentity, len(cs))
	for i, c := range cs {
		ocs[i] = oidc.ClientIdentity(c)
	}

	return NewClientIdentityRepo(ocs), nil
}

type clientIdentity oidc.ClientIdentity

func (ci *clientIdentity) UnmarshalJSON(data []byte) error {
	c := struct {
		ID          string `json:"id"`
		Secret      string `json:"secret"`
		RedirectURL string `json:"redirectURL"`
	}{}

	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}

	ru, err := url.Parse(c.RedirectURL)
	if err != nil {
		return err
	}

	ci.Credentials = oidc.ClientCredentials{
		ID:     c.ID,
		Secret: c.Secret,
	}
	ci.Metadata = oidc.ClientMetadata{
		RedirectURL: *ru,
	}

	return nil
}
