package connector

import (
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/health"
)

type Connector interface {
	health.Checkable
	LoginURL(sessionKey, prompt string) (string, error)
	Register(mux *http.ServeMux, errorURL url.URL)
}

type ConnectorConfig interface {
	ConnectorID() string
	ConnectorType() string
	Connector(url.URL, oidc.LoginFunc, *template.Template) (Connector, error)
}

type ConnectorConfigRepo interface {
	All() ([]ConnectorConfig, error)
}

type WritableConnectorCache interface {
	Write(string, string, interface{}, time.Time) error
}
