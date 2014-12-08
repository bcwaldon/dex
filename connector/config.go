package connector

import (
	"fmt"
)

type NewConnectorConfigFunc func() IDPConnectorConfig

var (
	ctypes map[string]NewConnectorConfigFunc
)

func RegisterConnectorConfigType(ctype string, fn NewConnectorConfigFunc) {
	if ctypes == nil {
		ctypes = make(map[string]NewConnectorConfigFunc)
	}

	if _, ok := ctypes[ctype]; ok {
		panic(fmt.Sprintf("connector config type %q already registered", ctype))
	}

	ctypes[ctype] = fn
}

func NewConnectorConfigFromType(ctype string) (IDPConnectorConfig, error) {
	fn, ok := ctypes[ctype]
	if !ok {
		return nil, fmt.Errorf("unrecognized connector config type %q", ctype)
	}

	return fn(), nil
}
