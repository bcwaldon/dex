package oidc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type JWT struct {
	RawToken  string
	Header    map[string]string
	Claims    map[string]string
	Signature []byte
}

func NewJWT() JWT {
	// TODO: implement
	return JWT{}
}

func ParseJWT(rawToken string) (JWT, error) {
	parts := strings.Split(rawToken, ".")

	header, err := DecodeHeader(parts[0])
	if err != nil {
		return JWT{}, err
	}

	//claims := parts[1]

	sig, err := DecodeSegment(parts[2])
	if err != nil {
		return JWT{}, err
	}

	jwt := JWT{
		RawToken: rawToken,
		Header:   header,
		//Claims:    claims,
		Signature: sig,
	}

	return jwt, nil
}

func (self JWT) RawData() string {
	return strings.Join(strings.Split(self.RawToken, ".")[0:2], ".")
}

func DecodeHeader(header string) (map[string]string, error) {
	var headerMap map[string]string

	headerBytes, err := DecodeSegment(header)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(headerBytes, &headerMap)
	if err != nil {
		return nil, err
	}
	return headerMap, nil
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
