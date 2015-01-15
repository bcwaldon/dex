package main

import (
	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/server"
)

func newDBDriver(dsn string) (driver, error) {
	dbc, err := db.NewConnection(dsn)
	if err != nil {
		return nil, err
	}

	drv := &dbDriver{
		ciRepo:  db.NewClientIdentityRepo(dbc),
		cfgRepo: db.NewConnectorConfigRepo(dbc),
	}

	return drv, nil
}

type dbDriver struct {
	ciRepo  server.ClientIdentityRepo
	cfgRepo *db.ConnectorConfigRepo
}

func (d *dbDriver) NewClient(meta oidc.ClientMetadata) (*oidc.ClientCredentials, error) {
	return d.ciRepo.New(meta)
}

func (d *dbDriver) ConnectorConfigs() ([]connector.ConnectorConfig, error) {
	return d.cfgRepo.All()
}

func (d *dbDriver) SetConnectorConfigs(cfgs []connector.ConnectorConfig) error {
	return d.cfgRepo.Set(cfgs)
}
