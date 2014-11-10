package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos-inc/auth/connector"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/server"

	// imported only so the connectors register themselves
	_ "github.com/coreos-inc/auth/connector/local"
)

var (
	staticKeyID = "2b3390f656ff335d6fdb8dfe117748c9f2709c02"
)

func main() {
	fs := flag.NewFlagSet("authd", flag.ExitOnError)
	fs.String("listen", "http://localhost:5556", "")
	fs.String("clients", "./authd/fixtures/clients.json", "json file containing set of clients")
	fs.String("connector-type", "local", "IdP connector type to configure")
	fs.String("connector-local-users", "./authd/fixtures/users.json", "json file containing set of users")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf(err.Error())
	}

	srv, err := newServerFromFlags(fs)
	if err != nil {
		log.Fatalf("Unable to build Server: %v", err)
	}

	listen := fs.Lookup("listen").Value.String()
	l, err := url.Parse(listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	_, p, err := net.SplitHostPort(l.Host)
	if err != nil {
		log.Fatalf("Unable to parse host from --listen flag: %v", err)
	}

	ct := fs.Lookup("connector-type").Value.String()
	idpc, err := connector.NewIDPConnector(ct, server.HttpPathAuthIDPC, srv.Login, fs)
	if err != nil {
		log.Fatalf("Unable to build IDPConnector: %v", err)
	}

	hdlr := srv.HTTPHandler(idpc)
	httpsrv := &http.Server{
		Addr:    fmt.Sprintf(":%s", p),
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
	ciRepo, err := server.NewClientIdentityRepoFromReader(cf)
	if err != nil {
		return nil, fmt.Errorf("unable to read client identities from file %s: %v", cFile, err)
	}

	signer := josesig.NewSignerRSA(staticKeyID, *privKey)
	sm := server.NewSessionManager(listen, signer)
	srv := server.Server{
		IssuerURL:          listen,
		Signer:             signer,
		SessionManager:     sm,
		ClientIdentityRepo: ciRepo,
	}
	return &srv, nil
}
