package oidc

import (
	"time"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
)

func NewSignedJWT(claims map[string]interface{}, s josesig.Signer) (*jose.JWT, error) {
	jwt := jose.JWT{
		Header: map[string]string{
			"alg": s.Alg(),
			"kid": s.ID(),
		},
		Claims: jose.Claims(claims),
	}

	sig, err := s.Sign([]byte(jwt.Data()))
	if err != nil {
		return nil, err
	}

	jwt.Signature = sig
	return &jwt, nil
}

type Session struct {
	AuthCode     string
	SubjectID    string
	ClientID     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	AccessToken  string
	RefreshToken string
}

func (ses *Session) IDToken(issuerURL string, signer josesig.Signer) (*jose.JWT, error) {
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
