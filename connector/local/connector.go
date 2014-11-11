package local

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

const (
	LocalIDPConnectorType = "local"

	// TODO(sym3tri): get from config once config is available
	loginPagePath = "./authd/fixtures/local-login.html"
)

func init() {
	connector.Register("local", NewLocalIDPConnectorFromFlags)
}

type LocalIDPConnector struct {
	idp       *LocalIdentityProvider
	namespace url.URL
	loginFunc oidc.LoginFunc
}

type Page struct {
	PostURL string
	Name    string
}

var templates *template.Template

func init() {
	var err error
	templates, err = template.ParseFiles(loginPagePath)
	if err != nil {
		log.Printf("no login page template: %s", err)
	}
}

func NewLocalIDPConnectorFromFlags(ns url.URL, lf oidc.LoginFunc, fs *flag.FlagSet) (connector.IDPConnector, error) {
	uFile := fs.Lookup("connector-local-users").Value.String()
	uf, err := os.Open(uFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read users from file %q: %v", uFile, err)
	}
	defer uf.Close()
	idp, err := NewLocalIdentityProviderFromReader(uf)
	if err != nil {
		return nil, fmt.Errorf("unable to build local identity provider from file %q: %v", uFile, err)
	}

	return NewLocalIDPConnector(ns, lf, idp), nil
}

func NewLocalIDPConnector(ns url.URL, lf oidc.LoginFunc, idp *LocalIdentityProvider) *LocalIDPConnector {
	return &LocalIDPConnector{
		idp:       idp,
		namespace: ns,
		loginFunc: lf,
	}
}

func (c *LocalIDPConnector) DisplayType() string {
	return "Local"
}

func (c *LocalIDPConnector) LoginURL(r *http.Request) string {
	return c.namespace.Path + "/login?" + r.URL.RawQuery
}

func (c *LocalIDPConnector) Register(mux *http.ServeMux) {
	mux.Handle(c.namespace.Path+"/login", handleLoginFunc(c.loginFunc, c.idp))
}

func handleLoginFunc(lf oidc.LoginFunc, idp *LocalIdentityProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			p := &Page{r.URL.String(), "Local"}
			if err := templates.ExecuteTemplate(w, "local-login.html", p); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if r.Method == "POST" {
			acr, err := oauth2.ParseAuthCodeRequest(r)
			if err != nil {
				phttp.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}

			userid := r.FormValue("userid")
			if userid == "" {
				phttp.WriteError(w, http.StatusBadRequest, "missing userid")
				return
			}

			password := r.FormValue("password")
			if password == "" {
				phttp.WriteError(w, http.StatusBadRequest, "missing password")
				return
			}

			ident := idp.Identity(userid, password)
			if ident == nil {
				phttp.WriteError(w, http.StatusBadRequest, "invalid login")
				return
			}

			code, err := lf(*ident, acr.ClientID)
			if err != nil {
				log.Printf("Unable to log in identity #%v with client ID %s", *ident, acr.ClientID)
				phttp.WriteError(w, http.StatusInternalServerError, "login failed")
				return
			}

			q := acr.RedirectURL.Query()
			q.Set("code", code)
			acr.RedirectURL.RawQuery = q.Encode()
			w.Header().Set("Location", acr.RedirectURL.String())

			w.WriteHeader(http.StatusTemporaryRedirect)

			return
		}

		phttp.WriteError(w, http.StatusBadRequest, "invalid method")
	}
}
