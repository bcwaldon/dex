package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JWT struct {
	Header    map[string]string
	Claims    map[string]string
	Signature []byte
}

func NewSignedJWT(claims map[string]string, s Signer) (*JWT, error) {
	jwt := JWT{
		Header: map[string]string{
			"alg": s.Alg(),
			"kid": s.ID(),
		},
		Claims: claims,
	}

	sig, err := s.Sign([]byte(jwt.Data()))
	if err != nil {
		return nil, err
	}

	jwt.Signature = sig
	return &jwt, nil
}

func (j *JWT) Data() string {
	mH := EncodeMap(j.Header)
	mC := EncodeMap(j.Claims)
	return strings.Join([]string{string(mH), string(mC)}, ".")
}

func (j *JWT) SignedData() string {
	d := j.Data()
	eS := EncodeSegment(j.Signature)
	return strings.Join([]string{d, string(eS)}, ".")
}

func ParseJWT(raw string) (jwt JWT, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		err = fmt.Errorf("malformed JWT, only %d segments", len(parts))
		return
	}

	jwt.Header, err = DecodeMap(parts[0])
	if err != nil {
		return
	}

	jwt.Claims, err = DecodeMap(parts[1])
	if err != nil {
		return
	}

	jwt.Signature, err = DecodeSegment(parts[2])
	if err != nil {
		return
	}

	return
}

func DecodeMap(seg string) (map[string]string, error) {
	var m map[string]string

	b, err := DecodeSegment(seg)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func EncodeMap(m map[string]string) string {
	b, err := json.Marshal(m)
	if err != nil {
		panic("failed encoding header!")
	}

	return EncodeSegment(b)
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l != 0 {
		seg += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(seg)
}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}
