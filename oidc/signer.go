package oidc

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
)

type Verifier interface {
	ID() string
	PubKey() crypto.PublicKey
	Alg() string
	Verify(signature []byte, data []byte) error
}

type Signer interface {
	Verifier
	Sign(data []byte) (sig []byte, err error)
	JWK() JWK
}

func NewVerifier(jwk JWK) (Verifier, error) {
	switch strings.ToUpper(jwk.Type) {
	case "RSA":
		return NewVerifierRSA(jwk.Alg, jwk.Modulus, jwk.Exponent, jwk.ID)
	default:
		return nil, errors.New("unsupported key type")
	}
}

// Turns a URL encoded exponent of a key into an int.
func DecodeExponent(e string) (int, error) {
	decE, err := base64.URLEncoding.DecodeString(e)
	if err != nil {
		return 0, err
	}
	var eBytes []byte
	if len(decE) < 8 {
		eBytes = make([]byte, 8-len(decE), 8)
		eBytes = append(eBytes, decE...)
	} else {
		eBytes = decE
	}
	eReader := bytes.NewReader(eBytes)
	var E uint64
	err = binary.Read(eReader, binary.BigEndian, &E)
	if err != nil {
		return 0, err
	}
	return int(E), nil
}

func EncodeExponent(e int) string {
	//TODO(bcwaldon): don't really need a full uint64 here
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(e))
	return base64.URLEncoding.EncodeToString(b)
}

// Turns a URL encoded modulus of a key into a big int.
func DecodeModulus(n string) (*big.Int, error) {
	decN, err := base64.URLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	N := big.NewInt(0)
	N.SetBytes(decN)
	return N, nil
}

func EncodeModulus(n *big.Int) string {
	return base64.URLEncoding.EncodeToString(n.Bytes())
}
