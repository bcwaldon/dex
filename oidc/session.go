package oidc

import (
	"time"
)

type Session struct {
	AuthCode     string
	SubjectID    string
	ClientID     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	AccessToken  string
	RefreshToken string
}

func (ses *Session) IDToken(issuerURL string, signer Signer) (*JWT, error) {
	claims := map[string]interface{}{
		// required
		"iss": issuerURL,
		"sub": ses.SubjectID,
		"aud": ses.ClientID,
		// explicitly cast to float64 for consistent JSON (de)serialization
		"exp": float64(ses.ExpiresAt.Unix()),
		"iat": float64(ses.IssuedAt.Unix()),

		// conventional
		"name":  "Elroy",
		"email": "elroy@example.com",
	}

	return NewSignedJWT(claims, signer)
}
