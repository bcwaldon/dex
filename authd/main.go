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

	"github.com/coreos-inc/auth/connector/local"
	josesig "github.com/coreos-inc/auth/jose/sig"
	"github.com/coreos-inc/auth/server"
)

var (
	staticKeyID = "2b3390f656ff335d6fdb8dfe117748c9f2709c02"
)

func main() {
	listen := flag.String("listen", "http://localhost:5556", "")
	uFile := flag.String("users", "./authd/fixtures/users.json", "json file containing set of users")
	cFile := flag.String("clients", "./authd/fixtures/clients.json", "json file containing set of clients")
	flag.Parse()

	l, err := url.Parse(*listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	_, p, err := net.SplitHostPort(l.Host)
	if err != nil {
		log.Fatalf("Unable to parse host from --listen flag: %v", err)
	}

	privKey, err := generateRSAPrivateKey()
	if err != nil {
		log.Fatalf("Unable to generate RSA private key: %v", err)
	}

	signer := josesig.NewSignerRSA(staticKeyID, *privKey)

	uf, err := os.Open(*uFile)
	if err != nil {
		log.Fatalf("Unable to read users from file %q: %v", *uFile, err)
	}
	defer uf.Close()
	idp, err := local.NewLocalIdentityProviderFromReader(uf)
	if err != nil {
		log.Fatalf("Unable to build local identity provider from file %q: %v", *uFile, err)
	}
	idpc := &local.LocalIDPConnector{idp}

	cf, err := os.Open(*cFile)
	if err != nil {
		log.Fatalf("Unable to read clients from file %s: %v", *cFile, err)
	}
	defer cf.Close()
	ciRepo, err := server.NewClientIdentityRepoFromReader(cf)
	if err != nil {
		log.Fatalf("Unable to read client identities from file %s: %v", *cFile, err)
	}

	sm := server.NewSessionManager(*listen, signer)

	srv := server.Server{
		IssuerURL:          *listen,
		Signer:             signer,
		SessionManager:     sm,
		IDPConnector:       idpc,
		ClientIdentityRepo: ciRepo,
	}
	hdlr := srv.HTTPHandler()
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
