package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/oauth2"
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

	clientID, err := randString(32)
	if err != nil {
		stderr("Failed generating random client ID: %v", err)
		return 1
	}
	host := redirectURL.Host
	if strings.Contains(host, ":") {
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			stderr("Failed parsing URL hostname: %v", err)
			return 1
		}
	}
	clientID = fmt.Sprintf("%s@%s", clientID, host)

	clientSecret, err := randString(128)
	if err != nil {
		stderr("Failed generating random client ID: %v", err)
		return 1
	}

	ci := oauth2.ClientIdentity{
		ID:          clientID,
		Secret:      clientSecret,
		RedirectURL: *redirectURL,
	}

	r := db.NewClientIdentityRepo(dbc)
	if err := r.Create(ci); err != nil {
		stderr(err.Error())
		return 1
	}

	stdout("Added new client:")
	stdout("ID:          %s", ci.ID)
	stdout("Secret:      %s", ci.Secret)
	stdout("RedirectURL: %s", ci.RedirectURL.String())

	return 0
}
