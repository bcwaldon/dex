package key

import (
	"errors"

	"github.com/coreos-inc/auth/jose"
	josesig "github.com/coreos-inc/auth/jose/sig"
)

type KeyManager interface {
	Signer() (josesig.Signer, error)
	JWKs() []jose.JWK
}

func NewRSAKeyManager() *RSAKeyManager {
	return &RSAKeyManager{}
}

type RSAKeyManager struct {
	current *RSAKey
	keys    []RSAKey
}

func (m *RSAKeyManager) Signer() (josesig.Signer, error) {
	if m.current == nil {
		return nil, errors.New("unable to determine signing key")
	}

	return m.current.Signer(), nil
}

func (m *RSAKeyManager) Set(keys []RSAKey, current *RSAKey) {
	m.current = current
	m.keys = keys
}

func (s *RSAKeyManager) JWKs() []jose.JWK {
	jwks := make([]jose.JWK, len(s.keys))
	for i, k := range s.keys {
		jwks[i] = k.JWK()
	}
	return jwks
}
