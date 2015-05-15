package main

import (
	"errors"
	"net/http"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/oidc"
	schema "github.com/coreos-inc/auth/schema/workerschema"
)

func newAPIDriver(pcfg oidc.ProviderConfig, creds oidc.ClientCredentials) (driver, error) {
	ccfg := oidc.ClientConfig{
		ProviderConfig: pcfg,
		Credentials:    creds,
	}
	oc, err := oidc.NewClient(ccfg)
	if err != nil {
		return nil, err
	}

	trans := &oidc.AuthenticatedTransport{
		TokenRefresher: &oidc.ClientCredsTokenRefresher{
			Issuer:     pcfg.Issuer,
			OIDCClient: oc,
		},
		RoundTripper: http.DefaultTransport,
	}
	hc := &http.Client{Transport: trans}
	svc, err := schema.NewWithBasePath(hc, pcfg.Issuer)
	if err != nil {
		return nil, err
	}

	return &apiDriver{svc: svc}, nil
}

type apiDriver struct {
	svc *schema.Service
}

func (d *apiDriver) NewClient(meta oidc.ClientMetadata) (*oidc.ClientCredentials, error) {
	sc := &schema.Client{
		RedirectURIs: make([]string, len(meta.RedirectURLs)),
	}

	for i, u := range meta.RedirectURLs {
		sc.RedirectURIs[i] = u.String()
	}

	call := d.svc.Clients.Create(sc)
	scs, err := call.Do()
	if err != nil {
		return nil, err
	}

	creds := &oidc.ClientCredentials{
		ID:     scs.Id,
		Secret: scs.Secret,
	}

	return creds, nil
}

func (d *apiDriver) ConnectorConfigs() ([]connector.ConnectorConfig, error) {
	return nil, errors.New("unable to get connector configs from HTTP API")
}

func (d *apiDriver) SetConnectorConfigs(cfgs []connector.ConnectorConfig) error {
	return errors.New("unable to set connector configs through HTTP API")
}
