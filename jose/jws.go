package jose

import (
	"errors"
	"fmt"
	"strings"
)

type JWS struct {
	RawHeader  string
	Header     map[string]string
	RawPayload string
	Payload    []byte
	Signature  []byte
}

// Given a raw JWS token parses it and verifies the structure.
func ParseJWS(token string) (JWS, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWS{}, fmt.Errorf("malformed JWS, only %d segments", len(parts))
	}

	rawSig := parts[2]
	jws := JWS{
		RawHeader:  parts[0],
		RawPayload: parts[1],
	}

	header, err := DecodeHeader(jws.RawHeader)
	if err != nil {
		return JWS{}, errors.New("malformed JWS, unable to decode header")
	}
	if err = ValidateHeader(header); err != nil {
		return JWS{}, fmt.Errorf("malformed JWS, %s", err)
	}
	jws.Header = header

	payload, err := DecodeSegment(jws.RawPayload)
	if err != nil {
		return JWS{}, fmt.Errorf("malformed JWS, unable to decode payload: %s", err)
	}
	jws.Payload = payload

	sig, err := DecodeSegment(rawSig)
	if err != nil {
		return JWS{}, fmt.Errorf("malformed JWS, unable to decode signature: %s", err)
	}
	jws.Signature = sig

	return jws, nil
}

// Validate that a decoded header has all required params.
func ValidateHeader(header map[string]string) error {
	if _, exists := header["alg"]; !exists {
		return errors.New("header missing 'alg' parameter")
	}

	return nil
}
