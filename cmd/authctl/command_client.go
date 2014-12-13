package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
)

var (
	cmdNewClient = &command{
		Name:    "new-client",
		Summary: "Create a new client ID and secret",
		Usage:   "<URL>",
		Run:     runNewClient,
	}
)

func init() {
	commands = append(commands, cmdNewClient)
}

func runNewClient(args []string) int {
	if len(args) != 1 {
		stderr("Provide a single argument.")
		return 2
	}

	redirectURL, err := url.Parse(args[0])
	if err != nil {
		stderr("Malformed redirectURL %q: %v", args[0], err)
		return 1
	}

	dbc, err := db.NewConnection(global.dbURL)
	if err != nil {
		stderr("Failed initializing connection with database: %v", err)
		return 1
	}

	clientID, err := genClientID(redirectURL.Host)
	if err != nil {
		stderr("Failed generating client ID: %v", err)
		return 1
	}

	clientSecret, err := randBytes(128)
	if err != nil {
		stderr("Failed generating client secret: %v", err)
		return 1
	}

	ci := oidc.ClientIdentity{
		Credentials: oauth2.ClientCredentials{
			ID:     clientID,
			Secret: base64.URLEncoding.EncodeToString(clientSecret),
		},
		Metadata: oidc.ClientMetadata{
			RedirectURL: *redirectURL,
		},
	}

	r := db.NewClientIdentityRepo(dbc)
	if err := r.Create(ci); err != nil {
		stderr(err.Error())
		return 1
	}

	stdout("Added new client:")
	stdout("ID:          %s", ci.Credentials.ID)
	stdout("Secret:      %s", ci.Credentials.Secret)
	stdout("RedirectURL: %s", ci.Metadata.RedirectURL.String())

	return 0
}

func genClientID(hostport string) (string, error) {
	b, err := randBytes(32)
	if err != nil {
		return "", err
	}

	var host string
	if strings.Contains(hostport, ":") {
		host, _, err = net.SplitHostPort(hostport)
		if err != nil {
			return "", err
		}
	} else {
		host = hostport
	}

	return fmt.Sprintf("%s@%s", base64.URLEncoding.EncodeToString(b), host), nil
}
