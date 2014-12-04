package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/coreos-inc/auth/connector"
	connectorlocal "github.com/coreos-inc/auth/connector/local"
	connectoroidc "github.com/coreos-inc/auth/connector/oidc"
	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	pflag "github.com/coreos-inc/auth/pkg/flag"
	"github.com/coreos-inc/auth/pkg/health"
	"github.com/coreos-inc/auth/server"
	"github.com/coreos-inc/auth/session"
)

const (
	LoginPageTemplateName = "login.html"
)

var (
	dbURLFlag string
	useDB     bool
)

func main() {
	fs := flag.NewFlagSet("authd", flag.ExitOnError)
	fs.String("listen", "http://0.0.0.0:5556", "")
	fs.String("issuer", "http://127.0.0.1:5556", "")
	fs.String("clients", "./static/fixtures/clients.json", "json file containing set of clients")
	fs.String("html-assets", "./static/html", "directory of html template files")
	fs.String("db-url", "", "DSN-formatted database connection string")
	fs.Bool("no-db", false, "manage entities in-process w/o any encryption, used only for single-node testing")
	fs.String("key-secret", "", "symmetric key used to encrypt/decrypt signing key data in DB")

	fs.String("connector-type", "local", "IdP connector type to configure")
	fs.String("connector-local-users", "./static/fixtures/users.json", "json file containing set of users")
	fs.String("connector-id", "id", "unique id of the connector")
	fs.String("connector-oidc-issuer-url", "https://accounts.google.com", "")
	fs.String("connector-oidc-client-id", "", "")
	fs.String("connector-oidc-client-secret", "", "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatalf(err.Error())
	}

	if err := pflag.SetFlagsFromEnv(fs, "AUTHD"); err != nil {
		log.Fatalf(err.Error())
	}

	listen := fs.Lookup("listen").Value.String()
	lu, err := url.Parse(listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	if lu.Scheme != "http" {
		log.Fatalf("Unable to listen using scheme %s", lu.Scheme)
	}

	dbURLFlag, useDB, err = parseDBFlags(fs)
	if err != nil {
		log.Fatalf("Unable to parse DB flags: %v", err)
	}

	km, err := newKeyManagerFromFlags(fs)
	if err != nil {
		log.Fatalf("Unable to build KeyManager: %v", err)
	}

	tpls, err := newHTMLTemplatesFromFlags(fs)
	if err != nil {
		log.Fatalf("Unable to parse HTML templates: %v", err)
	}

	srv, err := newServerFromFlags(fs, km, tpls)
	if err != nil {
		log.Fatalf("Unable to build Server: %v", err)
	}

	idpcs, err := newIDPConnectorsFromFlags(fs, srv.Login, tpls)
	if err != nil {
		log.Fatalf("Unable to build IDPConnector: %v", err)
	}

	checks := []health.Checkable{km}
	for _, idpc := range idpcs {
		checks = append(checks, health.Checkable(idpc))
	}
	if useDB {
		dbc, err := db.NewHealthChecker(dbURLFlag)
		if err != nil {
			log.Fatalf("Unable to build DB health checker: %v", err)
		}
		checks = append(checks, dbc)
	}

	hdlr := srv.HTTPHandler(idpcs, checks)
	httpsrv := &http.Server{
		Addr:    lu.Host,
		Handler: hdlr,
	}

	log.Printf("binding to %s...", httpsrv.Addr)
	log.Fatal(httpsrv.ListenAndServe())
}

func parseDBFlags(fs *flag.FlagSet) (string, bool, error) {
	no, err := strconv.ParseBool(fs.Lookup("no-db").Value.String())
	if err != nil {
		return "", false, fmt.Errorf("failed parsing --no-db: %v", err)
	}

	dbURL := fs.Lookup("db-url").Value.String()
	if !no && len(dbURL) == 0 {
		return "", false, errors.New("--db-url unset")
	}

	if no {
		log.Printf("WARNING: running in-process withour external database or key rotation")
	}

	return dbURL, !no, nil
}

func getSecretFlag(fs *flag.FlagSet) (sec string, err error) {
	sec = fs.Lookup("key-secret").Value.String()
	if len(sec) == 0 {
		err = errors.New("--key-secret unset")
	}
	return
}

func newKeyManagerFromFlags(fs *flag.FlagSet) (key.PrivateKeyManager, error) {
	var kRepo key.PrivateKeySetRepo
	if useDB {
		sec, err := getSecretFlag(fs)
		if err != nil {
			return nil, err
		}

		kRepo, err = db.NewPrivateKeySetRepo(dbURLFlag, sec)
		if err != nil {
			return nil, err
		}
	} else {
		kRepo = key.NewPrivateKeySetRepo()

		// WARNING: the following behavior is just for testing - do not rely on this
		k, err := key.GeneratePrivateRSAKey()
		if err != nil {
			return nil, err
		}
		ks := key.NewPrivateKeySet([]key.PrivateKey{k}, time.Now().Add(24*time.Hour))
		if err = kRepo.Set(ks); err != nil {
			return nil, err
		}
	}

	km := key.NewPrivateKeyManager()
	key.NewKeySetSyncer(kRepo, km).Run()

	return km, nil
}

func newServerFromFlags(fs *flag.FlagSet, km key.PrivateKeyManager, tpls *template.Template) (*server.Server, error) {
	var err error
	var ciRepo server.ClientIdentityRepo
	if useDB {
		ciRepo, err = db.NewClientIdentityRepo(dbURLFlag)
		if err != nil {
			return nil, err
		}
	} else {
		cFile := fs.Lookup("clients").Value.String()
		cf, err := os.Open(cFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read clients from file %s: %v", cFile, err)
		}
		defer cf.Close()
		ciRepo, err = newClientIdentityRepoFromReader(cf)
		if err != nil {
			return nil, fmt.Errorf("unable to read client identities from file %s: %v", cFile, err)
		}
	}

	var sRepo session.SessionRepo
	var skRepo session.SessionKeyRepo
	if useDB {
		sRepo, err = db.NewSessionRepo(dbURLFlag)
		if err != nil {
			return nil, fmt.Errorf("unable to create SessionRepo: %v", err)
		}
		skRepo, err = db.NewSessionKeyRepo(dbURLFlag)
		if err != nil {
			return nil, fmt.Errorf("unable to create SessionKeyRepo: %v", err)
		}
	} else {
		sRepo = session.NewSessionRepo()
		skRepo = session.NewSessionKeyRepo()
	}

	tpl := tpls.Lookup(LoginPageTemplateName)
	if tpl == nil {
		return nil, errors.New("unable to find necessary HTML template")
	}

	sm := session.NewSessionManager(sRepo, skRepo)
	issuer := fs.Lookup("issuer").Value.String()
	srv := server.Server{
		IssuerURL:          issuer,
		KeyManager:         km,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
		LoginTemplate:      tpl,
	}
	return &srv, nil
}

func newHTMLTemplatesFromFlags(fs *flag.FlagSet) (*template.Template, error) {
	sa := fs.Lookup("html-assets").Value.String()
	files := []string{
		path.Join(sa, LoginPageTemplateName),
		path.Join(sa, connectorlocal.LoginPageTemplateName),
	}
	return template.ParseFiles(files...)
}

func newIDPConnectorsFromFlags(fs *flag.FlagSet, lf oidc.LoginFunc, tpls *template.Template) (map[string]connector.IDPConnector, error) {
	issuer := fs.Lookup("issuer").Value.String()
	ns, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}

	idpcID := fs.Lookup("connector-id").Value.String()
	if idpcID == "" {
		log.Fatalf("Missing --connector-id flag")
	}

	ns.Path = path.Join(ns.Path, server.HttpPathAuth, strings.ToLower(idpcID))

	var cfg connector.IDPConnectorConfig
	switch fs.Lookup("connector-type").Value.String() {
	case connectorlocal.LocalIDPConnectorType:
		uFile := fs.Lookup("connector-local-users").Value.String()
		users, err := connectorlocal.ReadUsersFromFile(uFile)
		if err != nil {
			return nil, err
		}
		cfg = &connectorlocal.LocalIDPConnectorConfig{
			Users: users,
		}
	case connectoroidc.OIDCIDPConnectorType:
		cfg = &connectoroidc.OIDCIDPConnectorConfig{
			IssuerURL:    fs.Lookup("connector-oidc-issuer-url").Value.String(),
			ClientID:     fs.Lookup("connector-oidc-client-id").Value.String(),
			ClientSecret: fs.Lookup("connector-oidc-client-secret").Value.String(),
		}
	default:
		return nil, errors.New("unrecognized --connector-type value")
	}

	idpc, err := cfg.Connector(*ns, lf, tpls)
	if err != nil {
		return nil, err
	}

	return map[string]connector.IDPConnector{idpcID: idpc}, nil
}

func newClientIdentityRepoFromReader(r io.Reader) (server.ClientIdentityRepo, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var cs []clientIdentity
	if err = json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}

	ocs := make([]oauth2.ClientIdentity, len(cs))
	for i, c := range cs {
		ocs[i] = oauth2.ClientIdentity(c)
	}

	return server.NewClientIdentityRepo(ocs), nil
}

type clientIdentity oauth2.ClientIdentity

func (ci *clientIdentity) UnmarshalJSON(data []byte) error {
	c := struct {
		ID          string `json:"id"`
		Secret      string `json:"secret"`
		RedirectURL string `json:"redirectURL"`
	}{}

	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}

	ru, err := url.Parse(c.RedirectURL)
	if err != nil {
		return err
	}

	ci.ID = c.ID
	ci.Secret = c.Secret
	ci.RedirectURL = *ru

	return nil
}
