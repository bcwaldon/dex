package oidc

import (
	"errors"
	"strings"
)

// JSON Web Key
// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-36#page-5
type JWK struct {
	Type     string `json:"kty"`
	Alg      string `json:"alg"`
	Use      string `json:"use"`
	ID       string `json:"kid"`
	Exponent string `json:"e"`
	Modulus  string `json:"n"`
	// TODO: add Expires
}

// Construct a new Signer from a JWK
func NewJWKSigner(jwk JWK) (Signer, error) {
	switch strings.ToUpper(jwk.Type) {
	case "RSA":
		return NewSignerRSA(jwk.Alg, jwk.Modulus, jwk.Exponent, jwk.ID)
	default:
		return nil, errors.New("unsupported key type")
	}
}
