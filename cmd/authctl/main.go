package main

import (
	"errors"
	"flag"
	"os"

	pflag "github.com/coreos-inc/auth/pkg/flag"
)

var (
	cliName        = "authctl"
	cliDescription = "???"

	commands []*command
	globalFS = flag.NewFlagSet(cliName, flag.ExitOnError)

	global struct {
		dbURL string
		help  bool
	}
)

func init() {
	globalFS.StringVar(&global.dbURL, "db-url", "", "DSN-formatted database connection string")
	globalFS.BoolVar(&global.help, "help", false, "Print usage information and exit")
	globalFS.BoolVar(&global.help, "h", false, "Print usage information and exit")
}

func main() {
	err := parseFlags()
	if err != nil {
		stderr(err.Error())
		os.Exit(2)
	}

	args := globalFS.Args()
	if len(args) < 1 || global.help {
		args = []string{"help"}
	}

	var cmd *command
	for _, c := range commands {
		if c.Name == args[0] {
			cmd = c
			if err := c.Flags.Parse(args[1:]); err != nil {
				stderr("%v", err)
				os.Exit(2)
			}
			break
		}
	}

	if cmd == nil {
		stderr("%v: unknown subcommand: %q", cliName, args[0])
		stderr("Run '%v help' for usage.", cliName)
		os.Exit(2)
	}

	os.Exit(cmd.Run(cmd.Flags.Args()))
}

type command struct {
	Name        string       // Name of the command and the string to use to invoke it
	Summary     string       // One-sentence summary of what the command does
	Usage       string       // Usage options/arguments
	Description string       // Detailed description of command
	Flags       flag.FlagSet // Set of flags associated with this command

	Run func(args []string) int // Run a command with the given arguments, return exit status

}

func parseFlags() (err error) {
	if err = globalFS.Parse(os.Args[1:]); err != nil {
		return
	}

	if err = pflag.SetFlagsFromEnv(globalFS, "AUTHCTL"); err != nil {
		return
	}

	if len(global.dbURL) == 0 {
		err = errors.New("--db-url unset")
		return
	}

	return
}
