package main

import (
	"flag"
	"os"
	"time"

	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/key"
	pflag "github.com/coreos-inc/auth/pkg/flag"
	"github.com/coreos-inc/auth/pkg/log"
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

	gc.Run()
	<-krot.Run()
}
