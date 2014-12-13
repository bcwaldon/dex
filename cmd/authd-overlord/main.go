package main

import (
	"flag"
	"fmt"
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

	logDebug := fs.Bool("log-debug", false, "log debug-level information")
	logTimestamps := fs.Bool("log-timestamps", false, "prefix log lines with timestamps")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := pflag.SetFlagsFromEnv(fs, "AUTHD_OVERLORD"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if *logDebug {
		log.EnableDebug()
	}
	if *logTimestamps {
		log.EnableTimestamps()
	}

	if len(*secret) == 0 {
		log.Fatalf("--key-secret unset")
	}

	dbc, err := db.NewConnection(*dbURL)
	if err != nil {
		log.Fatalf(err.Error())
	}

	gc := db.NewGarbageCollector(dbc, *gcInterval)

	kRepo, err := db.NewPrivateKeySetRepo(dbc, *secret)
	if err != nil {
		log.Fatalf(err.Error())
	}
	krot := key.NewPrivateKeyRotator(kRepo, *keyPeriod)

	gc.Run()
	<-krot.Run()
}
