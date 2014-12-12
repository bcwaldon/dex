package main

import (
	"fmt"
	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/db"
)

var (
	cmdGetConnectorConfigs = &command{
		Name:    "get-connector-configs",
		Summary: "Enumerate current IdP connector configs.",
		Usage:   "",
		Run:     runGetConnectorConfigs,
	}

	cmdSetConnectorConfigs = &command{
		Name:    "set-connector-configs",
		Summary: "Overwrite the current IdP connector configs with those from a local file.",
		Usage:   "<FILE>",
		Run:     runSetConnectorConfigs,
	}
)

func init() {
	commands = append(commands, cmdSetConnectorConfigs)
	commands = append(commands, cmdGetConnectorConfigs)
}

func runSetConnectorConfigs(args []string) int {
	if len(args) != 1 {
		stderr("Provide a single argument.")
		return 2
	}

	rf, err := connector.NewConnectorConfigRepoFromFile(args[0])
	if err != nil {
		stderr("Unable to retrieve configs from file: %v", err)
		return 1
	}

	cfgs, err := rf.All()
	if err != nil {
		stderr("Unable to retrieve configs from file: %v", err)
		return 1
	}

	dbc, err := db.NewConnection(global.dbURL)
	if err != nil {
		stderr("Failed initializing connection with database: %v", err)
		return 1
	}

	r := db.NewConnectorConfigRepo(dbc)
	if err := r.Set(cfgs); err != nil {
		stderr(err.Error())
		return 1
	}

	fmt.Printf("Saved %d connector config(s)\n", len(cfgs))

	return 0
}

func runGetConnectorConfigs(args []string) int {
	if len(args) != 0 {
		stderr("Provide zero arguments.")
		return 2
	}

	dbc, err := db.NewConnection(global.dbURL)
	if err != nil {
		stderr("Failed initializing connection with database: %v", err)
		return 1
	}

	r := db.NewConnectorConfigRepo(dbc)
	cfgs, err := r.All()
	if err != nil {
		stderr("Unable to retrieve configs from repo: %v", err)
		return 1
	}

	fmt.Printf("Found %d connector config(s)\n", len(cfgs))

	for _, cfg := range cfgs {
		fmt.Println()
		fmt.Printf("ID:   %v\n", cfg.ConnectorID())
		fmt.Printf("Type: %v\n", cfg.ConnectorType())
	}

	return 0
}
