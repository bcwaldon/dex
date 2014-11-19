package key

import (
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"

	"github.com/coreos-inc/auth/jose"
)

func TestPrivateRSAKeyJWK(t *testing.T) {
	n := big.NewInt(int64(17))
	if n == nil {
		panic("NewInt returned nil")
	}

	k := &privateRSAKey{
		id: "foo",
		privateKey: &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: 65537},
		},
	}

	want := jose.JWK{
		ID:       "foo",
		Type:     "RSA",
		Alg:      "RS256",
		Use:      "sig",
		Modulus:  n,
		Exponent: 65537,
	}

	got := k.JWK()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("JWK mismatch: want=%#v got=%#v", want, got)
	}
}
