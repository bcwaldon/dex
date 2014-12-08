package connector

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

func newConnectorConfigsFromReader(r io.Reader) ([]ConnectorConfig, error) {
	var ms []map[string]interface{}
	if err := json.NewDecoder(r).Decode(&ms); err != nil {
		return nil, err
	}
	cfgs := make([]ConnectorConfig, len(ms))
	for i, m := range ms {
		cfg, err := newConnectorConfigFromMap(m)
		if err != nil {
			return nil, err
		}
		cfgs[i] = cfg
	}
	return cfgs, nil
}

func newConnectorConfigFromMap(m map[string]interface{}) (ConnectorConfig, error) {
	ityp, ok := m["type"]
	if !ok {
		return nil, errors.New("connector config type not set")
	}
	typ, ok := ityp.(string)
	if !ok {
		return nil, errors.New("connector config type not string")
	}
	cfg, err := NewConnectorConfigFromType(typ)
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

func NewConnectorConfigRepoFromFile(loc string) (ConnectorConfigRepo, error) {
	cf, err := os.Open(loc)
	if err != nil {
		return nil, err
	}
	defer cf.Close()

	cfgs, err := newConnectorConfigsFromReader(cf)
	if err != nil {
		return nil, err
	}

	return &memConnectorConfigRepo{configs: cfgs}, nil
}

type memConnectorConfigRepo struct {
	configs []ConnectorConfig
}

func (r *memConnectorConfigRepo) All() ([]ConnectorConfig, error) {
	return r.configs, nil
}
