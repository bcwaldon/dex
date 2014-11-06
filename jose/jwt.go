package jose

import (
	"fmt"
	"strings"
)

type Claims map[string]interface{}

type JWT struct {
	Header    map[string]string
	Claims    Claims
	Signature []byte
}

func (j *JWT) Data() string {
	mH := EncodeHeader(j.Header)
	mC := EncodeClaims(j.Claims)
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

	jwt.Header, err = DecodeHeader(parts[0])
	if err != nil {
		return
	}

	jwt.Claims, err = DecodeClaims(parts[1])
	if err != nil {
		return
	}

	jwt.Signature, err = DecodeSegment(parts[2])
	if err != nil {
		return
	}

	return
}
