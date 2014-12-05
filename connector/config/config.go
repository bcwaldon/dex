package config

import (
	"encoding/json"
	"errors"
	"io"

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

func NewIDPConnectorConfigsFromReader(r io.Reader) ([]connector.IDPConnectorConfig, error) {
	var ms []map[string]interface{}
	if err := json.NewDecoder(r).Decode(&ms); err != nil {
		return nil, err
	}
	cfgs := make([]connector.IDPConnectorConfig, len(ms))
	for i, m := range ms {
		cfg, err := newIDPConnectorConfigFromMap(m)
		if err != nil {
			return nil, err
		}
		cfgs[i] = cfg
	}
	return cfgs, nil
}

func newIDPConnectorConfigFromMap(m map[string]interface{}) (connector.IDPConnectorConfig, error) {
	ityp, ok := m["type"]
	if !ok {
		return nil, errors.New("connector config type not set")
	}
	typ, ok := ityp.(string)
	if !ok {
		return nil, errors.New("connector config type not string")
	}
	cfg, err := NewConfigFromType(typ)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
