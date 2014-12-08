package connector

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

const (
	ConnectorTypeLocal    = "local"
	LoginPageTemplateName = "local-login.html"
)

func init() {
	RegisterConnectorConfigType(ConnectorTypeLocal, func() IDPConnectorConfig { return &ConnectorConfigLocal{} })
}

type ConnectorConfigLocal struct {
	ID    string `json:"id"`
	Users []User `json:"users"`
}

func (cfg *ConnectorConfigLocal) ConnectorID() string {
	return cfg.ID
}

func (cfg *ConnectorConfigLocal) ConnectorType() string {
	return ConnectorTypeLocal
}

func (cfg *ConnectorConfigLocal) Connector(ns url.URL, lf oidc.LoginFunc, tpls *template.Template) (IDPConnector, error) {
	tpl := tpls.Lookup(LoginPageTemplateName)
	if tpl == nil {
		return nil, fmt.Errorf("unable to find necessary HTML template")
	}

	idp := NewLocalIdentityProvider(cfg.Users)
	idpc := &LocalIDPConnector{
		idp:       idp,
		namespace: ns,
		loginFunc: lf,
		loginTpl:  tpl,
	}

	return idpc, nil
}

type LocalIDPConnector struct {
	idp       *LocalIdentityProvider
	namespace url.URL
	loginFunc oidc.LoginFunc
	loginTpl  *template.Template
}

type Page struct {
	PostURL string
	Name    string
	Error   bool
	Message string
}

func (c *LocalIDPConnector) DisplayType() string {
	return "Local"
}

func (c *LocalIDPConnector) Healthy() error {
	return nil
}

func (c *LocalIDPConnector) LoginURL(sessionKey, prompt string) (string, error) {
	q := url.Values{}
	q.Set("session_key", sessionKey)
	q.Set("prompt", prompt)
	enc := q.Encode()

	return path.Join(c.namespace.Path, "login") + "?" + enc, nil
}

func (c *LocalIDPConnector) Register(mux *http.ServeMux, errorURL url.URL) {
	route := c.namespace.Path + "/login"
	mux.Handle(route, handleLoginFunc(c.loginFunc, c.loginTpl, c.idp, route, errorURL))
}

func redirectPostError(w http.ResponseWriter, errorURL url.URL, q url.Values) {
	redirectURL := phttp.MergeQuery(errorURL, q)
	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusSeeOther)
}

func handleLoginFunc(lf oidc.LoginFunc, tpl *template.Template, idp *LocalIdentityProvider, localErrorPath string, errorURL url.URL) http.HandlerFunc {
	handleGET := func(w http.ResponseWriter, r *http.Request, errMsg string) {
		p := &Page{PostURL: r.URL.String(), Name: "Local"}
		if errMsg != "" {
			p.Error = true
			p.Message = errMsg
		}

		if err := tpl.Execute(w, p); err != nil {
			phttp.WriteError(w, http.StatusInternalServerError, err.Error())
		}
	}

	handlePOST := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			msg := fmt.Sprintf("unable to parse form from body: %v", err)
			phttp.WriteError(w, http.StatusBadRequest, msg)
			return
		}

		userid := r.PostForm.Get("userid")
		if userid == "" {
			handleGET(w, r, "missing userid")
			return
		}

		password := r.PostForm.Get("password")
		if password == "" {
			handleGET(w, r, "missing password")
			return
		}

		ident := idp.Identity(userid, password)
		if ident == nil {
			handleGET(w, r, "invalid login")
			return
		}

		q := r.URL.Query()
		sessionKey := r.FormValue("session_key")
		if sessionKey == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "missing session_key")
			redirectPostError(w, errorURL, q)
			return
		}

		redirectURL, err := lf(*ident, sessionKey)
		if err != nil {
			log.Printf("Unable to log in %#v: %v", *ident, err)
			q.Set("error", oauth2.ErrorAccessDenied)
			q.Set("error_description", "login failed")
			redirectPostError(w, errorURL, q)
			return
		}

		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			handlePOST(w, r)
		case "GET":
			handleGET(w, r, "")
		default:
			w.Header().Set("Allow", "GET, POST")
			phttp.WriteError(w, http.StatusMethodNotAllowed, "GET and POST only acceptable methods")
		}
	}
}

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u User) Identity() oidc.Identity {
	return oidc.Identity{
		ID:    u.ID,
		Name:  u.Name,
		Email: u.Email,
	}
}

func ReadUsersFromFile(loc string) ([]User, error) {
	uf, err := os.Open(loc)
	if err != nil {
		return nil, fmt.Errorf("unable to read users from file %q: %v", loc, err)
	}
	defer uf.Close()

	b, err := ioutil.ReadAll(uf)
	if err != nil {
		return nil, err
	}

	var us []User
	err = json.Unmarshal(b, &us)
	return us, err
}

func NewLocalIdentityProvider(users []User) *LocalIdentityProvider {
	p := LocalIdentityProvider{
		users: make(map[string]User, len(users)),
	}

	for _, u := range users {
		u := u
		p.users[u.ID] = u
	}

	return &p
}

type LocalIdentityProvider struct {
	users map[string]User
}

func (m *LocalIdentityProvider) Identity(id, password string) *oidc.Identity {
	u, ok := m.users[id]
	if !ok || u.Password != password {
		return nil
	}

	ident := u.Identity()
	return &ident
}
