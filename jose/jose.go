package jose

import (
	"encoding/base64"
	"encoding/json"
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
