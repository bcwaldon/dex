package jose

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Claims map[string]interface{}

type JWT struct {
	RawHeader  string
	Header     map[string]string
	RawPayload string
	Signature  []byte
	Claims     Claims
}

func ParseJWT(token string) (jwt JWT, err error) {
	jws, err := ParseJWS(token)
	if err != nil {
		return
	}

	// Convert parsed JWS to JWT
	jwt.RawHeader = jws.RawHeader
	jwt.Header = jws.Header
	jwt.RawPayload = jws.RawPayload
	jwt.Signature = jws.Signature

	// Extend with Claims
	jwt.Claims, err = DecodeClaims(jws.Payload)
	if err != nil {
		return
	}

	return
}

// Encoded data part of the token which may be signed.
func (j *JWT) Data() string {
	return strings.Join([]string{j.RawHeader, j.RawPayload}, ".")
}

// Full encoded JWT token string in format: header.claims.signature
func (j *JWT) Token() string {
	d := j.Data()
	s := EncodeSegment(j.Signature)
	return strings.Join([]string{d, s}, ".")
}

func DecodeClaims(payload []byte) (Claims, error) {
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("malformed JWT claims, unable to decode: %v", err)
	}
	return c, nil
}

func EncodeClaims(c Claims) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	return EncodeSegment(b), nil
}
