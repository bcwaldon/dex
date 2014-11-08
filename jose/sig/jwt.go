package sig

import (
	"github.com/coreos-inc/auth/jose"
)

func NewSignedJWT(claims map[string]interface{}, s Signer) (*jose.JWT, error) {
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
