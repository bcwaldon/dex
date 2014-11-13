package local

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/coreos-inc/auth/connector"
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

func (c *LocalIDPConnector) LoginURL(sessionKey string) (string, error) {
	q := url.Values{}
	q.Set("session_key", sessionKey)
	enc := q.Encode()

	return path.Join(c.namespace.Path, "login") + "?" + enc, nil
}

func (c *LocalIDPConnector) Register(mux *http.ServeMux) {
	mux.Handle(c.namespace.Path+"/login", handleLoginFunc(c.loginFunc, c.idp))
}

func handleLoginFunc(lf oidc.LoginFunc, idp *LocalIdentityProvider) http.HandlerFunc {
	handlePOST := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			msg := fmt.Sprintf("unable to parse form from body: %v", err)
			phttp.WriteError(w, http.StatusBadRequest, msg)
			return
		}

		userid := r.PostForm.Get("userid")
		if userid == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing userid")
			return
		}

		password := r.PostForm.Get("password")
		if password == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing password")
			return
		}

		ident := idp.Identity(userid, password)
		if ident == nil {
			phttp.WriteError(w, http.StatusBadRequest, "invalid login")
			return
		}

		sessionKey := r.FormValue("session_key")
		if sessionKey == "" {
			phttp.WriteError(w, http.StatusBadRequest, "missing session_key")
			return
		}

		redirectURL, err := lf(*ident, sessionKey)
		if err != nil {
			log.Printf("Unable to log in %#v: %v", *ident, err)
			phttp.WriteError(w, http.StatusInternalServerError, "login failed")
			return
		}

		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}

	handleGET := func(w http.ResponseWriter, r *http.Request) {
		p := &Page{r.URL.String(), "Local"}
		if err := templates.ExecuteTemplate(w, "local-login.html", p); err != nil {
			phttp.WriteError(w, http.StatusInternalServerError, err.Error())
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			handlePOST(w, r)
		case "GET":
			handleGET(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET and POST only acceptable methods")
		}
	}
}
