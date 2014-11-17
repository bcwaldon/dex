package key

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
)

type RSAKey struct {
	ID         string
	PrivateKey *rsa.PrivateKey
}

func (k *RSAKey) Signer() josesig.Signer {
	return josesig.NewSignerRSA(k.ID, *k.PrivateKey)
}

func (k *RSAKey) JWK() jose.JWK {
	return jose.JWK{
		ID:       k.ID,
		Type:     "RSA",
		Alg:      "RS256",
		Use:      "sig",
		Exponent: k.PrivateKey.PublicKey.E,
		Modulus:  k.PrivateKey.PublicKey.N,
	}
}

func GenerateRSAKey() (*RSAKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	k := RSAKey{
		ID:         base64BigInt(pk.PublicKey.N),
		PrivateKey: pk,
	}

	return &k, nil
}

func base64BigInt(b *big.Int) string {
	return base64.URLEncoding.EncodeToString(b.Bytes())
}
