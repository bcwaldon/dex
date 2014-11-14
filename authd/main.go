package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/coreos-inc/auth/connector"
	localconnector "github.com/coreos-inc/auth/connector/local"
	oidcconnector "github.com/coreos-inc/auth/connector/oidc"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/server"
	"github.com/coreos-inc/auth/session"
)

var (
	staticKeyID = "2b3390f656ff335d6fdb8dfe117748c9f2709c02"
)

func init() {
	connector.Register(localconnector.LocalIDPConnectorType, localconnector.NewLocalIDPConnectorFromFlags)
	connector.Register(oidcconnector.OIDCIDPConnectorType, oidcconnector.NewOIDCIDPConnectorFromFlags)
}

func main() {
	fs := flag.NewFlagSet("authd", flag.ExitOnError)
	fs.String("listen", "http://localhost:5556", "")
	fs.String("clients", "./authd/fixtures/clients.json", "json file containing set of clients")

	fs.String("connector-type", "local", "IdP connector type to configure")
	fs.String("connector-local-users", "./authd/fixtures/users.json", "json file containing set of users")
	fs.String("connector-oidc-issuer-url", "https://accounts.google.com", "")
	fs.String("connector-oidc-client-id", "", "")
	fs.String("connector-oidc-client-secret", "", "")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf(err.Error())
	}

	srv, err := newServerFromFlags(fs)
	if err != nil {
		log.Fatalf("Unable to build Server: %v", err)
	}

	listen := fs.Lookup("listen").Value.String()
	lu, err := url.Parse(listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	if lu.Scheme != "http" {
		log.Fatalf("Unable to listen using scheme %s", lu.Scheme)
	}

	idpc, err := newIDPConnectorFromFlags(fs, srv.Login)
	if err != nil {
		log.Fatalf("Unable to build IDPConnector: %v", err)
	}

	hdlr := srv.HTTPHandler(idpc)
	httpsrv := &http.Server{
		Addr:    lu.Host,
		Handler: hdlr,
	}

	log.Printf("binding to %s...", httpsrv.Addr)
	log.Fatal(httpsrv.ListenAndServe())
}

func generateRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(crand.Reader, 1024)
}

func newServerFromFlags(fs *flag.FlagSet) (*server.Server, error) {
	listen := fs.Lookup("listen").Value.String()

	privKey, err := generateRSAPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to generate RSA private key: %v", err)
	}

	cFile := fs.Lookup("clients").Value.String()
	cf, err := os.Open(cFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read clients from file %s: %v", cFile, err)
	}
	defer cf.Close()
	ciRepo, err := newClientIdentityRepoFromReader(cf)
	if err != nil {
		return nil, fmt.Errorf("unable to read client identities from file %s: %v", cFile, err)
	}

	signer := josesig.NewSignerRSA(staticKeyID, *privKey)
	sm := session.NewSessionManager()
	srv := server.Server{
		IssuerURL:          listen,
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}
	return &srv, nil
}

func newIDPConnectorFromFlags(fs *flag.FlagSet, lf oidc.LoginFunc) (connector.IDPConnector, error) {
	listen := fs.Lookup("listen").Value.String()
	ns, err := url.Parse(listen)
	if err != nil {
		return nil, err
	}

	ns.Path = path.Join(ns.Path, server.HttpPathAuthIDPC)

	ct := fs.Lookup("connector-type").Value.String()
	return connector.NewIDPConnector(ct, *ns, lf, fs)
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
