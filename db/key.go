package db

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/key"
	pcrypto "github.com/coreos-inc/auth/pkg/crypto"
)

const (
	keyTableName = "key"
)

func init() {
	register(table{
		name:    keyTableName,
		model:   privateKeySetBlob{},
		autoinc: false,
		pkey:    []string{"value"},
	})
}

func newPrivateKeySetModel(pks *key.PrivateKeySet) (*privateKeySetModel, error) {
	pkeys := pks.Keys()
	keys := make([]privateKeyModel, len(pkeys))
	for i, pkey := range pkeys {
		keys[i] = privateKeyModel{
			ID:    pkey.ID(),
			PKCS1: x509.MarshalPKCS1PrivateKey(pkey.PrivateKey),
		}
	}

	m := privateKeySetModel{
		Keys:      keys,
		ExpiresAt: pks.ExpiresAt(),
	}

	return &m, nil
}

type privateKeyModel struct {
	ID    string `json:"id"`
	PKCS1 []byte `json:"pkcs1"`
}

func (m *privateKeyModel) PrivateKey() (*key.PrivateKey, error) {
	d, err := x509.ParsePKCS1PrivateKey(m.PKCS1)
	if err != nil {
		return nil, err
	}

	pk := key.PrivateKey{
		KeyID:      m.ID,
		PrivateKey: d,
	}

	return &pk, nil
}

type privateKeySetModel struct {
	Keys      []privateKeyModel `json:"keys"`
	ExpiresAt time.Time         `json:"expiresAt"`
}

func (m *privateKeySetModel) PrivateKeySet() (*key.PrivateKeySet, error) {
	keys := make([]*key.PrivateKey, len(m.Keys))
	for i, pkm := range m.Keys {
		pk, err := pkm.PrivateKey()
		if err != nil {
			return nil, err
		}
		keys[i] = pk
	}
	return key.NewPrivateKeySet(keys, m.ExpiresAt), nil
}

type privateKeySetBlob struct {
	Value []byte `db:"value"`
}

func NewPrivateKeySetRepo(dbm *gorp.DbMap, secret string) (*PrivateKeySetRepo, error) {
	bsecret := []byte(secret)
	if len(bsecret) != 32 {
		return nil, errors.New("expected 32-byte secret")
	}

	r := &PrivateKeySetRepo{
		dbMap:  dbm,
		secret: []byte(secret),
	}

	return r, nil
}

type PrivateKeySetRepo struct {
	dbMap  *gorp.DbMap
	secret []byte
}

func (r *PrivateKeySetRepo) Set(ks key.KeySet) error {
	_, err := r.dbMap.Exec("DELETE FROM key")
	if err != nil {
		return err
	}

	pks, ok := ks.(*key.PrivateKeySet)
	if !ok {
		return errors.New("unable to cast to PrivateKeySet")
	}

	m, err := newPrivateKeySetModel(pks)
	if err != nil {
		return err
	}

	j, err := json.Marshal(m)
	if err != nil {
		return err
	}

	v, err := pcrypto.AESEncrypt(j, r.secret)
	if err != nil {
		return err
	}

	b := &privateKeySetBlob{Value: v}
	return r.dbMap.Insert(b)
}

func (r *PrivateKeySetRepo) Get() (key.KeySet, error) {
	objs, err := r.dbMap.Select(&privateKeySetBlob{}, "SELECT * FROM key")
	if err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, key.ErrorNoKeys
	}

	b, ok := objs[0].(*privateKeySetBlob)
	if !ok {
		return nil, errors.New("unable to cast to KeySet")
	}

	j, err := pcrypto.AESDecrypt(b.Value, r.secret)
	if err != nil {
		return nil, errors.New("unable to decrypt key set")
	}

	var m privateKeySetModel
	if err := json.Unmarshal(j, &m); err != nil {
		return nil, err
	}

	pks, err := m.PrivateKeySet()
	if err != nil {
		return nil, err
	}

	return key.KeySet(pks), nil
}
