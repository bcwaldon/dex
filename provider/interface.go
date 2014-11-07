package provider

import (
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oidc"
)

type Provider interface {
	Config() oidc.ProviderConfig
	Signer() sig.Signer
	PublicKeys() []jose.JWK

	NewSession(Client, User) string
	Session(code string) *Session

	Client(clientID string) *Client
	User(userID string) *User
}
