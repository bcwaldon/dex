package oidc

// JSON Web Key
// https://tools.ietf.org/html/draft-ietf-jose-json-web-key-36#page-5
type JWK struct {
	Type     string `json:"kty"`
	Alg      string `json:"alg"`
	Use      string `json:"use"`
	ID       string `json:"kid"`
	Exponent string `json:"e"`
	Modulus  string `json:"n"`
}
