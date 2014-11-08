package provider

import (
	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oidc"
)

type Provider interface {
	Config() oidc.ProviderConfig
	Signer() sig.Signer
	PublicKeys() []jose.JWK

	Client(clientID string) *Client
	NewSession(Client, oidc.Identity) string
	Session(code string) *Session

	IDPConnector() connector.IDPConnector
}
