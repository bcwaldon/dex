package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
)

type VerifierRSA struct {
	KeyID     string
	Hash      crypto.Hash
	PublicKey rsa.PublicKey
}

type SignerRSA struct {
	PrivateKey rsa.PrivateKey
	VerifierRSA
}

func NewVerifierRSA(alg, n, e, kid string) (*VerifierRSA, error) {
	E, err := DecodeExponent(e)
	if err != nil {
		return nil, err
	}

	N, err := DecodeModulus(n)
	if err != nil {
		return nil, err
	}

	rsaKey := rsa.PublicKey{N: N, E: E}

	s := &VerifierRSA{
		PublicKey: rsaKey,
		KeyID:     kid,
	}

	switch strings.ToUpper(alg) {
	case "RS256":
		s.Hash = crypto.SHA256
	default:
		return nil, errors.New("unsupported algorithm")
	}

	return s, nil
}

func NewSignerRSA(kid string, key rsa.PrivateKey) *SignerRSA {
	return &SignerRSA{
		PrivateKey: key,
		VerifierRSA: VerifierRSA{
			PublicKey: key.PublicKey,
			KeyID:     kid,
			Hash:      crypto.SHA256,
		},
	}
}

func (v *VerifierRSA) ID() string {
	return v.KeyID
}

func (v *VerifierRSA) Alg() string {
	return "RS256"
}

func (v *VerifierRSA) Verify(sig []byte, data []byte) error {
	h := v.Hash.New()
	h.Write(data)
	return rsa.VerifyPKCS1v15(&v.PublicKey, v.Hash, h.Sum(nil), sig)
}

func (s *SignerRSA) Sign(data []byte) ([]byte, error) {
	h := s.Hash.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, &s.PrivateKey, s.Hash, h.Sum(nil))
}

func (s *SignerRSA) JWK() JWK {
	return JWK{
		Type:     "RSA",
		Alg:      "RS256",
		Use:      "sig",
		ID:       s.KeyID,
		Exponent: EncodeExponent(s.VerifierRSA.PublicKey.E),
		Modulus:  EncodeModulus(s.VerifierRSA.PublicKey.N),
	}
}
