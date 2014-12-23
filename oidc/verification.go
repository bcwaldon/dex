package oidc

import (
	"errors"
	"fmt"
	"time"

	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	pnet "github.com/coreos-inc/auth/pkg/net"
)

func VerifySignature(jwt jose.JWT, keys []key.PublicKey) (bool, error) {
	jwtBytes := []byte(jwt.Data())
	for _, k := range keys {
		v, err := k.Verifier()
		if err != nil {
			return false, err
		}
		if v.Verify(jwt.Signature, jwtBytes) == nil {
			return true, nil
		}
	}
	return false, nil
}

// Verify claims in accordance with OIDC spec
// http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
func VerifyClaims(jwt jose.JWT, issuer, clientID string) error {
	now := time.Now().UTC()

	claims, err := jwt.Claims()
	if err != nil {
		return err
	}

	ident, err := IdentityFromClaims(claims)
	if err != nil {
		return err
	}

	if ident.ExpiresAt.Before(now) {
		return errors.New("token is expired")
	}

	// iss REQUIRED. Issuer Identifier for the Issuer of the response.
	// The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
	if iss, exists := claims["iss"].(string); exists {
		if !pnet.URLEqual(iss, issuer) {
			return fmt.Errorf("invalid claim value: 'iss'. expected=%s, found=%s.", issuer, iss)
		}
	} else {
		return errors.New("missing claim: 'iss'")
	}

	// iat REQUIRED. Time at which the JWT was issued.
	// Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	if _, exists := claims["iat"].(float64); !exists {
		return errors.New("missing claim: 'iat'")
	}

	// aud REQUIRED. Audience(s) that this ID Token is intended for.
	// It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
	if aud, exists := claims["aud"].(string); exists {
		if aud != clientID {
			return errors.New("invalid claim value: 'aud'")
		}
	} else {
		return errors.New("missing claim: 'aud'")
	}

	return nil
}
