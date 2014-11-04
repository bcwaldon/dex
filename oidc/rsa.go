package oidc

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"strings"
)

type SignerRSA struct {
	RSAKey  rsa.PublicKey
	Hash    crypto.Hash
	AlgName string
	KeyID   string
}

func NewSignerRSA(alg, n, e, kid string) (*SignerRSA, error) {
	rsaKey, err := MakeRSAPubKey(n, e)
	if err != nil {
		return nil, err
	}

	s := &SignerRSA{
		RSAKey:  rsaKey,
		KeyID:   kid,
		AlgName: alg,
	}

	switch strings.ToUpper(alg) {
	case "RS256":
		s.Hash = crypto.SHA256
	default:
		return nil, errors.New("unsupported algorithm")
	}

	return s, nil
}

func (self *SignerRSA) ID() string {
	return self.KeyID
}

func (self *SignerRSA) MakeKey(n, e string) error {
	key, err := MakeRSAPubKey(n, e)
	if err != nil {
		return err
	}
	self.RSAKey = key
	return nil
}

func (self *SignerRSA) Key() crypto.PublicKey {
	return self.RSAKey
}

func (self *SignerRSA) Alg() string {
	return self.AlgName
}

func (self *SignerRSA) Verify(signature []byte, data string) error {
	h := self.Hash.New()
	h.Write([]byte(data))
	return rsa.VerifyPKCS1v15(&self.RSAKey, self.Hash, h.Sum(nil), signature)
}

// Make an RSA public key using exponent and modulus
func MakeRSAPubKey(n, e string) (rsa.PublicKey, error) {
	E, err := DecodeExponent(e)
	if err != nil {
		return rsa.PublicKey{}, err
	}

	N, err := DecodeModulus(n)
	if err != nil {
		return rsa.PublicKey{}, err
	}

	return rsa.PublicKey{N: N, E: E}, nil
}
