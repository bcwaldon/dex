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

	for _, ru := range sc.RedirectURIs {
		if ru == "" {
			continue
		}
		u, err := url.Parse(ru)
		if err != nil {
			continue
		}
		ci.Metadata.RedirectURLs = append(ci.Metadata.RedirectURLs, *u)
	}

	if len(ci.Metadata.RedirectURLs) == 0 {
		return oidc.ClientIdentity{}, errors.New("need at least one redirect URL")
	}

	return ci, nil
}

func MapClientIdentityToSchemaClient(c oidc.ClientIdentity) Client {
	cl := Client{
		Id:           c.Credentials.ID,
		RedirectURIs: make([]string, len(c.Metadata.RedirectURLs)),
	}
	for i, u := range c.Metadata.RedirectURLs {
		cl.RedirectURIs[i] = u.String()
	}
	return cl
}

func MapClientIdentityToSchemaClientWithSecret(c oidc.ClientIdentity) ClientWithSecret {
	cl := ClientWithSecret{
		Id:           c.Credentials.ID,
		Secret:       c.Credentials.Secret,
		RedirectURIs: make([]string, len(c.Metadata.RedirectURLs)),
	}
	for i, u := range c.Metadata.RedirectURLs {
		cl.RedirectURIs[i] = u.String()
	}
	return cl
}
