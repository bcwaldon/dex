package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
)

func DecodeHeader(seg string) (map[string]string, error) {
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

func EncodeHeader(m map[string]string) string {
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

func DecodeClaims(seg string) (Claims, error) {
	b, err := DecodeSegment(seg)
	if err != nil {
		return nil, errors.New("unable to parse JWT claims")
	}
	var c Claims
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("failed unmarshaling claims: %v", err)
	}

	return c, nil
}

func EncodeClaims(c Claims) string {
	b, err := json.Marshal(c)
	if err != nil {
		log.Fatalf("Failed encoding claims: %v", err)
	}

	return EncodeSegment(b)
}
