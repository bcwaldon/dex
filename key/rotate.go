package key

import (
	"errors"
	"log"
	"time"

	"github.com/jonboulle/clockwork"
)

const (
	DefaultKeyTTL = 12 * time.Hour
)

func NewPrivateKeyRotator(repo PrivateKeySetRepo, ttl time.Duration) *PrivateKeyRotator {
	return &PrivateKeyRotator{
		repo: repo,
		ttl:  ttl,

		keep:        2,
		generateKey: GeneratePrivateRSAKey,
		clock:       clockwork.NewRealClock(),
	}
}

type PrivateKeyRotator struct {
	repo        PrivateKeySetRepo
	generateKey GeneratePrivateRSAKeyFunc
	clock       clockwork.Clock
	keep        int
	ttl         time.Duration
}

func (r *PrivateKeyRotator) expiresAt() time.Time {
	return r.clock.Now().UTC().Add(r.ttl)
}

func (r *PrivateKeyRotator) Run() chan struct{} {
	attempt := func() {
		k, err := r.generateKey()
		if err != nil {
			log.Printf("Failed generating signing key: %v", err)
			return
		}

		exp := r.expiresAt()
		if err := rotatePrivateKeys(r.repo, k, r.keep, exp); err != nil {
			log.Printf("Failed key rotation: %v", err)
			return
		}

		log.Printf("Rotated signing keys: id=%s expiresAt=%s", k.ID(), exp)
	}

	stop := make(chan struct{})
	go func() {
		attempt()
		for {
			select {
			case <-r.clock.After(r.ttl / 2):
				attempt()
			case <-stop:
				return
			}
		}
	}()

	return stop
}

func rotatePrivateKeys(repo PrivateKeySetRepo, k PrivateKey, keep int, exp time.Time) error {
	ks, err := repo.Get()
	if err != nil {
		return err
	}

	pks, ok := ks.(*PrivateKeySet)
	if !ok {
		return errors.New("unable to cast to PrivateKeySet")
	}

	keys := append([]PrivateKey{k}, pks.Keys()...)
	if l := len(keys); l > keep {
		keys = keys[0:keep]
	}

	nks := PrivateKeySet{
		keys:        keys,
		activeKeyID: k.ID(),
		expiresAt:   exp,
	}

	return repo.Set(KeySet(&nks))
}
