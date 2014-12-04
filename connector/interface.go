package connector

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/health"
)

type IDPConnector interface {
	health.Checkable
	DisplayType() string
	LoginURL(sessionKey, prompt string) (string, error)
	Register(mux *http.ServeMux, errorURL url.URL)
}

type IDPConnectorConfig interface {
	ConnectorID() string
	Connector(url.URL, oidc.LoginFunc, *template.Template) (IDPConnector, error)
}
