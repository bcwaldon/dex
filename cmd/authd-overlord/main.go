package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oidc"
	pflag "github.com/coreos-inc/auth/pkg/flag"
)

func main() {
	fs := flag.NewFlagSet("authd-overlord", flag.ExitOnError)
	secret := fs.String("key-secret", "", "symmetric key used to encrypt/decrypt signing key data in DB")
	dbURL := fs.String("db-url", "", "DSN-formatted database connection string")
	keyPeriod := fs.Duration("key-period", 24*time.Hour, "length of time for-which a given key will be valid")
	gcInterval := fs.Duration("gc-interval", time.Hour, "length of time between garbage collection runs")

	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatalf(err.Error())
	}

	if err := pflag.SetFlagsFromEnv(fs, "AUTHD_OVERLORD"); err != nil {
		log.Fatalf(err.Error())
	}

	if len(*secret) == 0 {
		log.Fatalf("--key-secret unset")
	}

	kRepo, err := db.NewPrivateKeySetRepo(*dbURL, *secret)
	if err != nil {
		log.Fatalf(err.Error())
	}

	krot := key.NewPrivateKeyRotator(kRepo, *keyPeriod)

	gc, err := db.NewGarbageCollector(*dbURL, *gcInterval)
	if err != nil {
		log.Fatalf(err.Error())
	}

	cache, err := db.NewConnectorCache(*dbURL)
	if err != nil {
		log.Fatalf(err.Error())
	}

	cfgRepo, err := db.NewConnectorConfigRepo(*dbURL)
	if err != nil {
		log.Fatalf(err.Error())
	}

	cfgs, err := cfgRepo.All()
	if err != nil {
		log.Fatalf(err.Error())
	}

	for _, cfg := range cfgs {
		if cfg.ConnectorType() != connector.ConnectorTypeOIDC {
			continue
		}

		ocfg, ok := cfg.(*connector.ConnectorConfigOIDC)
		if !ok {
			log.Fatalf("Unable to cast OIDC connector config to proper type")
		}

		startOIDCSync(ocfg, cache)
	}

	gc.Run()
	<-krot.Run()
}

func startOIDCSync(cfg *connector.ConnectorConfigOIDC, cache connector.WritableConnectorCache) error {
	pcfg, err := oidc.FetchProviderConfig(http.DefaultClient, cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("unable to fetch provider config: %v", err)
	}

	idc := identifiedConnectorCache{cID: cfg.ConnectorID(), cache: cache}

	pr := oidc.NewHTTPProviderConfigGetter(http.DefaultClient, cfg.IssuerURL)
	pw := providerConfigRepo(idc)
	psync := oidc.NewProviderConfigSyncer(pr, &pw)

	kr := oidc.NewRemotePublicKeyRepo(http.DefaultClient, pcfg.KeysEndpoint)
	kw := publicKeySetRepo(idc)
	ksync := key.NewKeySetSyncer(kr, &kw)

	psync.Run()
	ksync.Run()

	return nil
}

type identifiedConnectorCache struct {
	cID   string
	cache connector.WritableConnectorCache
}

type publicKeySetRepo identifiedConnectorCache

func (r *publicKeySetRepo) Set(ks key.KeySet) error {
	return r.cache.Write(r.cID, "remoteJWKs", ks.JWKs(), ks.ExpiresAt())
}

type providerConfigRepo identifiedConnectorCache

func (r *providerConfigRepo) Set(pcfg oidc.ProviderConfig) error {
	return r.cache.Write(r.cID, "providerConfig", &pcfg, pcfg.ExpiresAt)
}
