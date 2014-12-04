package connector

import (
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/health"
)

var (
	types map[string]NewIDPConnectorFunc
)

func init() {
	types = map[string]NewIDPConnectorFunc{}
}

type NewIDPConnectorFunc func(url.URL, oidc.LoginFunc, *template.Template, *flag.FlagSet) (IDPConnector, error)

func Register(ct string, fn NewIDPConnectorFunc) {
	types[ct] = fn
}

type IDPConnector interface {
	health.Checkable
	DisplayType() string
	LoginURL(sessionKey, prompt string) (string, error)
	Register(mux *http.ServeMux, errorURL url.URL)
}

func NewIDPConnector(ct string, ns url.URL, lf oidc.LoginFunc, tpls *template.Template, fs *flag.FlagSet) (IDPConnector, error) {
	f, ok := types[ct]
	if !ok {
		return nil, fmt.Errorf("unknown type %q", ct)
	}

	return f(ns, lf, tpls, fs)
}
