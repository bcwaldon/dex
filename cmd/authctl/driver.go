package main

import (
	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/oidc"
)

type driver interface {
	NewClient(oidc.ClientMetadata) (*oidc.ClientCredentials, error)

	ConnectorConfigs() ([]connector.ConnectorConfig, error)
	SetConnectorConfigs([]connector.ConnectorConfig) error
}
