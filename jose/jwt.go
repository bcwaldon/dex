package jose

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var TimeFunc = time.Now

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

// Verify claims as specified in OIDC spec
// http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
func (self JWT) VerifyClaims(issuer, clientID string) error {
	now := TimeFunc().Unix()

	// iss REQUIRED. Issuer Identifier for the Issuer of the response.
	// The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
	if iss, exists := self.Claims["iss"].(string); exists {
		// TODO: clean & canonicalize strings
		if !URLEqual(iss, issuer) {
			return fmt.Errorf("invalid claim value: 'iss'. expected=%s, found=%s.", issuer, iss)
		}
	} else {
		return errors.New("missing claim: 'iss'")
	}

	// exp REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
	// The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
	// Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
	// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	// See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
	// TODO: is this method of type conversion safe?
	if exp, exists := self.Claims["exp"].(float64); exists {
		if now > int64(exp) {
			return errors.New("token is expired")
		}
	} else {
		return errors.New("missing claim: 'exp'")
	}

	// sub REQUIRED. Subject Identifier.
	// Locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4.
	// It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
	if _, exists := self.Claims["sub"].(string); !exists {
		return errors.New("missing claim: 'sub'")
	}

	// iat REQUIRED. Time at which the JWT was issued.
	// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	if _, exists := self.Claims["iat"].(float64); !exists {
		return errors.New("missing claim: 'iat'")
	}

	// aud REQUIRED. Audience(s) that this ID Token is intended for.
	// It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
	if aud, exists := self.Claims["aud"].(string); exists {
		// TODO: clean & canonicalize strings
		if aud != clientID {
			return errors.New("invalid claim value: 'aud'")
		}
	} else {
		return errors.New("missing claim: 'aud'")
	}

	// TODO: optional claims from OIDC spec
	// auth_time, nonce, at_hash, acr, amr, azp

	return nil
}
