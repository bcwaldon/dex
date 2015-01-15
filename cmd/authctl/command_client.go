package main

import (
	"net/url"

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

	cc, err := getDriver().NewClient(oidc.ClientMetadata{RedirectURL: *redirectURL})
	if err != nil {
		stderr("Failed creating new client: %v", err)
		return 1
	}

	stdout("Added new client:")
	stdout("ID:          %s", cc.ID)
	stdout("Secret:      %s", cc.Secret)
	stdout("RedirectURL: %s", redirectURL.String())

	return 0
}
