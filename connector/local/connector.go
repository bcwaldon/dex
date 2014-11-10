package local

import (
	"net/http"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

type LocalIDPConnector struct {
	*LocalIdentityProvider
	path      string
	loginFunc oidc.LoginFunc
}

func NewLocalIDPConnector(lidp *LocalIdentityProvider, path string, lf oidc.LoginFunc) *LocalIDPConnector {
	return &LocalIDPConnector{
		LocalIdentityProvider: lidp,
		path:      path,
		loginFunc: lf,
	}
}

func (c *LocalIDPConnector) DisplayType() string {
	return "Local"
}

func (c *LocalIDPConnector) LoginURL(r *http.Request) string {
	return c.path + "/login?" + r.URL.RawQuery
}

func (c *LocalIDPConnector) Register(mux *http.ServeMux) {
	mux.Handle(c.path+"/login", handleLoginFunc(c.loginFunc, c.LocalIdentityProvider))
}

func handleLoginFunc(lf oidc.LoginFunc, idp *LocalIdentityProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		acr, err := oauth2.ParseAuthCodeRequest(r)
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}

		id := r.URL.Query().Get("uid")
		if id == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing uid query param")
			return
		}

		ident := idp.Identity(id)
		if ident == nil {
			phttp.WriteError(w, http.StatusBadRequest, "unrecognized uid")
			return
		}

		lf(w, *acr, *ident)
	}
}
