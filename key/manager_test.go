package key

import (
	"crypto/rsa"
	"math/big"
	"reflect"
	"strconv"
	"testing"

	"github.com/coreos-inc/auth/jose"
)

func generateRSAKeyStatic(t *testing.T, idAndN int) *RSAKey {
	n := big.NewInt(int64(idAndN))
	if n == nil {
		t.Fatalf("Call to NewInt(%d) failed", idAndN)
	}

	pk := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: 65537},
	}

	return &RSAKey{
		ID:         strconv.Itoa(idAndN),
		PrivateKey: pk,
	}
}

func TestRSAKeyManagerJWKsRotate(t *testing.T) {
	k1 := generateRSAKeyStatic(t, 1)
	jwk1 := jose.JWK{
		ID:       "1",
		Type:     "RSA",
		Alg:      "RS256",
		Use:      "sig",
		Modulus:  big.NewInt(1),
		Exponent: 65537,
	}

	k2 := generateRSAKeyStatic(t, 2)
	jwk2 := jose.JWK{
		ID:       "2",
		Type:     "RSA",
		Alg:      "RS256",
		Use:      "sig",
		Modulus:  big.NewInt(2),
		Exponent: 65537,
	}

	k3 := generateRSAKeyStatic(t, 3)
	jwk3 := jose.JWK{
		ID:       "3",
		Type:     "RSA",
		Alg:      "RS256",
		Use:      "sig",
		Modulus:  big.NewInt(3),
		Exponent: 65537,
	}

	km := NewRSAKeyManager()
	km.Set([]RSAKey{*k1, *k2, *k3}, k1)

	want := []jose.JWK{jwk1, jwk2, jwk3}
	got := km.JWKs()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("JWK mismatch: want=%#v got=%#v", want, got)
	}
}

func TestRSAKeyManagerNoKeys(t *testing.T) {
	km := NewRSAKeyManager()
	s, err := km.Signer()
	if err == nil {
		t.Errorf("Expected non-nil error")
	}
	if s != nil {
		t.Errorf("Expected nil Signer")
	}

	jwks := km.JWKs()
	if len(jwks) != 0 {
		t.Errorf("Expected 0 JWKs, got %d", len(jwks))
	}
}

func TestRSAKeyManagerSigner(t *testing.T) {
	k := generateRSAKeyStatic(t, 13)

	km := NewRSAKeyManager()
	km.Set([]RSAKey{*k}, k)

	signer, err := km.Signer()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	wantID := "13"
	gotID := signer.ID()
	if wantID != gotID {
		t.Fatalf("Signer has incorrect ID: want=%s got=%s", wantID, gotID)
	}
}
