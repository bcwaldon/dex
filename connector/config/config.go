package config

import (
	"errors"

	"github.com/coreos-inc/auth/connector"
	connectorlocal "github.com/coreos-inc/auth/connector/local"
	connectoroidc "github.com/coreos-inc/auth/connector/oidc"
)

func NewConfigFromType(ctype string) (connector.IDPConnectorConfig, error) {
	switch ctype {
	case connectorlocal.LocalIDPConnectorType:
		return &connectorlocal.LocalIDPConnectorConfig{}, nil
	case connectoroidc.OIDCIDPConnectorType:
		return &connectoroidc.OIDCIDPConnectorConfig{}, nil
	}

	return nil, errors.New("unrecognized connector config type")
}
