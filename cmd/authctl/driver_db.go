package main

import (
	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/server"
	"github.com/coreos/go-oidc/oidc"
)

func newDBDriver(dsn string) (driver, error) {
	dbc, err := db.NewConnection(db.Config{DSN: dsn})
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
	if err := meta.Valid(); err != nil {
		return nil, err
	}

	clientID, err := oidc.GenClientID(meta.RedirectURLs[0].Host)
	if err != nil {
		return nil, err
	}

	return d.ciRepo.New(clientID, meta)
}

func (d *dbDriver) ConnectorConfigs() ([]connector.ConnectorConfig, error) {
	return d.cfgRepo.All()
}

func (d *dbDriver) SetConnectorConfigs(cfgs []connector.ConnectorConfig) error {
	return d.cfgRepo.Set(cfgs)
}
