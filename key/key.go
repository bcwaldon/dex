package key

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
)

type PublicKey interface {
	Verifier() (josesig.Verifier, error)
}

type publicRSAKey struct {
	jwk jose.JWK
}

func (k *publicRSAKey) Verifier() (josesig.Verifier, error) {
	return josesig.NewVerifierRSA(k.jwk)
}

type PrivateKey interface {
	ID() string
	Signer() josesig.Signer
	JWK() jose.JWK
}

type privateRSAKey struct {
	id         string
	privateKey *rsa.PrivateKey
}

func (k *privateRSAKey) ID() string {
	return k.id
}

func (k *privateRSAKey) Signer() josesig.Signer {
	return josesig.NewSignerRSA(k.ID(), *k.privateKey)
}

func (k *privateRSAKey) JWK() jose.JWK {
	return jose.JWK{
		ID:       k.id,
		Type:     "RSA",
		Alg:      "RS256",
		Use:      "sig",
		Exponent: k.privateKey.PublicKey.E,
		Modulus:  k.privateKey.PublicKey.N,
	}
}

type KeySet interface {
	ExpiresAt() time.Time
}

type PublicKeySet interface {
	KeySet
	Keys() []PublicKey
}

type publicRSAKeySet struct {
	keys []publicRSAKey
}

func (s *publicRSAKeySet) Keys() []PublicKey {
	pks := make([]PublicKey, len(s.keys))
	for i, rk := range s.keys {
		rk := rk
		pks[i] = PublicKey(&rk)
	}
	return pks
}

type PrivateKeySet struct {
	keys        []PrivateKey
	activeKeyID string
	expiresAt   time.Time
}

func NewPrivateKeySet(keys []PrivateKey, exp time.Time) *PrivateKeySet {
	return &PrivateKeySet{
		keys:        keys,
		activeKeyID: keys[0].ID(),
		expiresAt:   exp,
	}
}

func (s *PrivateKeySet) Keys() []PrivateKey {
	pks := make([]PrivateKey, len(s.keys))
	for i, rk := range s.keys {
		rk := rk
		pks[i] = PrivateKey(rk)
	}
	return pks
}

func (s *PrivateKeySet) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s *PrivateKeySet) Active() PrivateKey {
	for i, k := range s.keys {
		if k.ID() == s.activeKeyID {
			return PrivateKey(s.keys[i])
		}
	}

	return nil
}

type GeneratePrivateRSAKeyFunc func() (*privateRSAKey, error)

func GeneratePrivateRSAKey() (*privateRSAKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	k := privateRSAKey{
		id:         base64BigInt(pk.PublicKey.N),
		privateKey: pk,
	}

	return &k, nil
}

func base64BigInt(b *big.Int) string {
	return base64.URLEncoding.EncodeToString(b.Bytes())
}
