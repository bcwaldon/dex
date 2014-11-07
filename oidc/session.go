package oidc

import (
	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
)

func NewSignedJWT(claims map[string]interface{}, s josesig.Signer) (*jose.JWT, error) {
	header := jose.JOSEHeader{
		"alg": s.Alg(),
		"kid": s.ID(),
	}

	jwt, err := jose.NewJWT(header, jose.Claims(claims))
	if err != nil {
		return nil, err
	}

	sig, err := s.Sign([]byte(jwt.Data()))
	if err != nil {
		return nil, err
	}
	jwt.Signature = sig

	return &jwt, nil
}
