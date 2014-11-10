package connector

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/coreos-inc/auth/oidc"
)

var (
	types map[string]NewIDPConnectorFunc
)

func init() {
	types = map[string]NewIDPConnectorFunc{}
}

type NewIDPConnectorFunc func(string, oidc.LoginFunc, *flag.FlagSet) (IDPConnector, error)

func Register(ct string, fn NewIDPConnectorFunc) {
	types[ct] = fn
}

type IDPConnector interface {
	DisplayType() string
	LoginURL(r *http.Request) string
	Register(mux *http.ServeMux)
}

func NewIDPConnector(ct string, p string, lf oidc.LoginFunc, fs *flag.FlagSet) (IDPConnector, error) {
	f, ok := types[ct]
	if !ok {
		return nil, fmt.Errorf("unknown type %q", ct)
	}

	return f(p, lf, fs)
}
