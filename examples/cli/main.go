package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

func main() {
	fs := flag.NewFlagSet("example-cli", flag.ExitOnError)
	clientID := fs.String("client-id", "", "")
	clientSecret := fs.String("client-secret", "", "")
	discovery := fs.String("discovery", "http://localhost:5556", "")
	fs.Parse(os.Args[1:])

	if *clientID == "" {
		fmt.Println("--client-id must be set")
		os.Exit(2)
	}

	if *clientSecret == "" {
		fmt.Println("--client-secret must be set")
		os.Exit(2)
	}

	ci := oauth2.ClientIdentity{
		ID:     *clientID,
		Secret: *clientSecret,
	}

	// NOTE: A real CLI would cache this config, or provide it via flags/config file.
	var cfg oidc.ProviderConfig
	var err error
	for {
		cfg, err = oidc.FetchProviderConfig(http.DefaultClient, *discovery)
		if err == nil {
			break
		}

		sleep := 1 * time.Second
		fmt.Printf("Failed fetching provider config, trying again in %v: %v", sleep, err)
		time.Sleep(sleep)
	}

	fmt.Printf("Fetched provider config from %s: %#v\n\n", *discovery, cfg)

	client := &oidc.Client{
		ProviderConfig: cfg,
		ClientIdentity: ci,
	}

	// TODO(sym3tri): remove this hack once synchronous key-fetching is available.
	client.SyncKeys()
	time.Sleep(1 * time.Second)

	tok, err := client.ClientCredsToken([]string{"openid"})
	if err != nil {
		fmt.Printf("unable to verify auth code with issuer: %v", err)
		os.Exit(1)
	}

	fmt.Printf("got jwt: %v\n\n", tok.Encode())

	claims, err := tok.Claims()
	if err != nil {
		fmt.Printf("unable to construct claims: %v", err)
		os.Exit(1)
	}

	fmt.Printf("got claims %#v...", claims)
}