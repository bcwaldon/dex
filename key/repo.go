package key

import (
	"errors"
)

type WritableKeySetRepo interface {
	Set(KeySet) error
}

type ReadableKeySetRepo interface {
	Get() (KeySet, error)
}

type PrivateKeySetRepo interface {
	WritableKeySetRepo
	ReadableKeySetRepo
}

func NewPrivateKeySetRepo() PrivateKeySetRepo {
	return &memPrivateKeySetRepo{}
}

type memPrivateKeySetRepo struct {
	pks PrivateKeySet
}

func (r *memPrivateKeySetRepo) Set(ks KeySet) error {
	pks, ok := ks.(*PrivateKeySet)
	if !ok {
		return errors.New("unable to cast to PrivateKeySet")
	} else if pks == nil {
		return errors.New("nil KeySet")
	}

	r.pks = *pks
	return nil
}

func (r *memPrivateKeySetRepo) Get() (KeySet, error) {
	return KeySet(&r.pks), nil
}
