package connector

import (
	"errors"
)

func NewConfigFromType(ctype string) (IDPConnectorConfig, error) {
	switch ctype {
	case LocalIDPConnectorType:
		return &LocalIDPConnectorConfig{}, nil
	case OIDCIDPConnectorType:
		return &OIDCIDPConnectorConfig{}, nil
	}

	return nil, errors.New("unrecognized connector config type")
}
