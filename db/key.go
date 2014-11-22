package db

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/coopernurse/gorp"

	"github.com/coreos-inc/auth/key"
)

const (
	keyTableName = "key"
)

func newPrivateKeySetBlob(pks *key.PrivateKeySet) (*privateKeySetBlob, error) {
	pkeys := pks.Keys()
	keys := make([]privateKeyModel, len(pkeys))
	for i, pkey := range pkeys {
		rkey, ok := pkey.(*key.PrivateRSAKey)
		if !ok {
			return nil, errors.New("unable to cast to PrivateRSAKey")
		}
		keys[i] = privateKeyModel{
			ID:    pkey.ID(),
			PKCS1: x509.MarshalPKCS1PrivateKey(rkey.PrivateKey),
		}
	}
	m := privateKeySetModel{
		Keys:      keys,
		ExpiresAt: pks.ExpiresAt(),
	}

	b, err := json.Marshal(&m)
	if err != nil {
		return nil, err
	}

	mb := privateKeySetBlob{
		Value: b,
	}

	return &mb, nil
}

type privateKeyModel struct {
	ID    string `json:"id"`
	PKCS1 []byte `json:"pkcs1"`
}

func (m *privateKeyModel) PrivateRSAKey() (*key.PrivateRSAKey, error) {
	d, err := x509.ParsePKCS1PrivateKey(m.PKCS1)
	if err != nil {
		return nil, err
	}

	pk := key.PrivateRSAKey{
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
	keys := make([]key.PrivateKey, len(m.Keys))
	for i, pkm := range m.Keys {
		rk, err := pkm.PrivateRSAKey()
		if err != nil {
			return nil, err
		}
		keys[i] = key.PrivateKey(rk)
	}
	return key.NewPrivateKeySet(keys, m.ExpiresAt), nil
}

type privateKeySetBlob struct {
	Value []byte `db:"value"`
}

func (b *privateKeySetBlob) PrivateKeySet() (*key.PrivateKeySet, error) {
	var m privateKeySetModel
	if err := json.Unmarshal(b.Value, &m); err != nil {
		return nil, err
	}

	return m.PrivateKeySet()
}

func NewPrivateKeySetRepo(dsn string) (*PrivateKeySetRepo, error) {
	dbm, err := dbMap(dsn)
	if err != nil {
		return nil, err
	}

	dbm.AddTableWithName(privateKeySetBlob{}, keyTableName).SetKeys(false, "value")
	if err := dbm.CreateTablesIfNotExists(); err != nil {
		return nil, err
	}

	r := &PrivateKeySetRepo{
		dbMap: dbm,
	}

	return r, nil
}

type PrivateKeySetRepo struct {
	dbMap *gorp.DbMap
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

	b, err := newPrivateKeySetBlob(pks)
	if err != nil {
		return err
	}

	return r.dbMap.Insert(b)
}

func (r *PrivateKeySetRepo) Get() (key.KeySet, error) {
	objs, err := r.dbMap.Select(&privateKeySetBlob{}, "SELECT * FROM key")
	if err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, nil
	}

	m, ok := objs[0].(*privateKeySetBlob)
	if !ok {
		return nil, errors.New("unable to cast to KeySet")
	}

	pks, err := m.PrivateKeySet()
	if err != nil {
		return nil, err
	}

	return key.KeySet(pks), nil
}
