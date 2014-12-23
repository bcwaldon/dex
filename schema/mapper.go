package schema

import (
	"errors"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
)

func MapSchemaClientToClientIdentity(sc Client) (oidc.ClientIdentity, error) {
	ci := oidc.ClientIdentity{
		Credentials: oidc.ClientCredentials{
			ID: sc.Client_id,
		},
		Metadata: oidc.ClientMetadata{},
	}

	urlOK := false
	for _, ru := range sc.Redirect_uris {
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
		Client_id:     c.Credentials.ID,
		Client_secret: c.Credentials.Secret,
		Redirect_uris: []string{c.Metadata.RedirectURL.String()},
	}
}
