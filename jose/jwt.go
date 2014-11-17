package jose

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Claims map[string]interface{}

type JWT JWS

func ParseJWT(token string) (jwt JWT, err error) {
	jws, err := ParseJWS(token)
	if err != nil {
		return
	}

	return toJWT(jws)
}

func toJWT(jws JWS) (JWT, error) {
	if jws.Header["typ"] != "JWT" {
		return JWT{}, errors.New("unrecognized header typ")
	}

	return JWT(jws), nil
}

func NewJWT(header JOSEHeader, claims Claims) (jwt JWT, err error) {
	jwt = JWT{}

	jwt.Header = header
	jwt.Header["typ"] = "JWT"

	claimBytes, err := marshalClaims(claims)
	if err != nil {
		return
	}
	jwt.Payload = claimBytes

	eh, err := encodeHeader(header)
	if err != nil {
		return
	}
	jwt.RawHeader = eh

	ec, err := encodeClaims(claims)
	if err != nil {
		return
	}
	jwt.RawPayload = ec

	return
}

func (j *JWT) Claims() (Claims, error) {
	return decodeClaims(j.Payload)
}

// Encoded data part of the token which may be signed.
func (j *JWT) Data() string {
	return strings.Join([]string{j.RawHeader, j.RawPayload}, ".")
}

// Full encoded JWT token string in format: header.claims.signature
func (j *JWT) Encode() string {
	d := j.Data()
	s := encodeSegment(j.Signature)
	return strings.Join([]string{d, s}, ".")
}

func decodeClaims(payload []byte) (Claims, error) {
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("malformed JWT claims, unable to decode: %v", err)
	}
	return c, nil
}

func marshalClaims(c Claims) ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func encodeClaims(c Claims) (string, error) {
	b, err := marshalClaims(c)
	if err != nil {
		return "", err
	}

	return encodeSegment(b), nil
}
