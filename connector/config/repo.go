package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/coreos-inc/auth/connector"
)

func newIDPConnectorConfigsFromReader(r io.Reader) ([]connector.IDPConnectorConfig, error) {
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

func NewIDPConnectorConfigRepoFromFile(loc string) (connector.IDPConnectorConfigRepo, error) {
	cf, err := os.Open(loc)
	if err != nil {
		return nil, err
	}
	defer cf.Close()

	cfgs, err := newIDPConnectorConfigsFromReader(cf)
	if err != nil {
		return nil, err
	}

	return &memIDPConnectorConfigRepo{configs: cfgs}, nil
}

type memIDPConnectorConfigRepo struct {
	configs []connector.IDPConnectorConfig
}

func (r *memIDPConnectorConfigRepo) All() ([]connector.IDPConnectorConfig, error) {
	return r.configs, nil
}
