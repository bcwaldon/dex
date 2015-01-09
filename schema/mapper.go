package schema

import (
	"errors"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
)

func MapSchemaClientToClientIdentity(sc Client) (oidc.ClientIdentity, error) {
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID: sc.Id,
		},
		Metadata: oidc.ClientMetadata{},
	}

	urlOK := false
	for _, ru := range sc.RedirectURIs {
		if ru == "" {
			continue
		}
		u, err := url.Parse(ru)
		if err != nil {
			continue
		}
		ci.Metadata.RedirectURL = *u
		urlOK = true
	}
	if !urlOK {
		return oidc.ClientIdentity{}, errors.New("invalid callback URLs")
	}

	return ci, nil
}

func MapClientIdentityToSchemaClient(c oidc.ClientIdentity) Client {
	return Client{
		Id:           c.Credentials.ID,
		RedirectURIs: []string{c.Metadata.RedirectURL.String()},
	}
}

func MapClientIdentityToSchemaClientWithSecret(c oidc.ClientIdentity) ClientWithSecret {
	return ClientWithSecret{
		Id:           c.Credentials.ID,
		Secret:       c.Credentials.Secret,
		RedirectURIs: []string{c.Metadata.RedirectURL.String()},
	}
}
