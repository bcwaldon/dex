package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"

	pflag "github.com/coreos-inc/auth/pkg/flag"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos-inc/auth/server"
)

func main() {
	fs := flag.NewFlagSet("authd-worker", flag.ExitOnError)
	listen := fs.String("listen", "http://0.0.0.0:5556", "")
	issuer := fs.String("issuer", "http://127.0.0.1:5556", "")
	templates := fs.String("html-assets", "./static/html", "directory of html template files")
	noDB := fs.Bool("no-db", false, "manage entities in-process w/o any encryption, used only for single-node testing")

	// ignored if --no-db is set
	dbURL := fs.String("db-url", "", "DSN-formatted database connection string")
	keySecret := fs.String("key-secret", "", "symmetric key used to encrypt/decrypt signing key data in DB")

	// used only if --no-db is set
	connectors := fs.String("connectors", "./static/fixtures/connectors.json", "JSON file containg set of IDPC configs")
	clients := fs.String("clients", "./static/fixtures/clients.json", "json file containing set of clients")

	logDebug := fs.Bool("log-debug", false, "log debug-level information")
	logTimestamps := fs.Bool("log-timestamps", false, "prefix log lines with timestamps")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := pflag.SetFlagsFromEnv(fs, "AUTHD_WORKER"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if *logDebug {
		log.EnableDebug()
	}
	if *logTimestamps {
		log.EnableTimestamps()
	}

	lu, err := url.Parse(*listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	if lu.Scheme != "http" {
		log.Fatalf("Unable to listen using scheme %s", lu.Scheme)
	}

	var scfg server.ServerConfig
	if *noDB {
		log.Warning("Running in-process without external database or key rotation")
		scfg = &server.SingleServerConfig{
			IssuerURL:      *issuer,
			TemplateDir:    *templates,
			ClientsFile:    *clients,
			ConnectorsFile: *connectors,
		}
	} else {
		scfg = &server.MultiServerConfig{
			IssuerURL:   *issuer,
			TemplateDir: *templates,
			KeySecret:   *keySecret,
			DatabaseURL: *dbURL,
		}
	}

	srv, err := scfg.Server()
	if err != nil {
		log.Fatalf("Unable to build Server: %v", err)
	}

	cfgs, err := srv.ConnectorConfigRepo.All()
	if err != nil {
		log.Fatalf("Unable to fetch connector configs from repo: %v", err)
	}

	for _, cfg := range cfgs {
		cfg := cfg
		if err = srv.AddConnector(cfg); err != nil {
			log.Fatalf("Failed registering connector: %v", err)
		}
	}

	httpsrv := &http.Server{
		Addr:    lu.Host,
		Handler: srv.HTTPHandler(),
	}

	log.Infof("Binding to %s...", httpsrv.Addr)
	go func() {
		log.Fatal(httpsrv.ListenAndServe())
	}()

	<-srv.Run()
}
