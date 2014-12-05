package oidc

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coreos-inc/auth/jose"
)

func ParseTokenFromRequest(r *http.Request) (token jose.JWT, err error) {
	ah := r.Header.Get("Authorization")
	if ah == "" {
		err = errors.New("missing Authorization header")
		return
	}

	if len(ah) <= 6 || strings.ToUpper(ah[0:6]) != "BEARER" {
		err = errors.New("should be a bearer token")
		return
	}

	return jose.ParseJWT(ah[7:])
}

func NewClaims(iss, sub, aud string, iat, exp time.Time) jose.Claims {
	return jose.Claims{
		// required
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": float64(iat.Unix()),
		"exp": float64(exp.Unix()),
	}
}
