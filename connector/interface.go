package connector

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/health"
)

type Connector interface {
	ID() string
	LoginURL(sessionKey, prompt string) (string, error)
	Register(mux *http.ServeMux, errorURL url.URL)

	// Sync triggers any long-running tasks needed to maintain the
	// Connector's operation. For example, this would encompass
	// repeatedly caching any remote resources for local use.
	Sync() chan struct{}

	health.Checkable
}

type ConnectorConfig interface {
	ConnectorID() string
	ConnectorType() string
	Connector(url.URL, oidc.LoginFunc, *template.Template) (Connector, error)
}

type ConnectorConfigRepo interface {
	All() ([]ConnectorConfig, error)
}
