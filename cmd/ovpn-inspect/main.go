package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hamedsanaei/openvpn-go/profile"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ovpn-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rootPath := flags.String("root", "", "authorized directory for referenced material")
	err := flags.Parse(args)
	if err != nil || flags.NArg() != 1 {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "Usage: ovpn-inspect [-root directory] profile.ovpn|-")
			return 0
		}
		fmt.Fprintln(stderr, "Usage: ovpn-inspect [-root directory] profile.ovpn|-")
		return 2
	}

	r := stdin
	if name := flags.Arg(0); name != "-" {
		file, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(stderr, "ovpn-inspect: could not open profile")
			return 1
		}
		defer file.Close()
		r = file
	}
	var opts profile.Options
	if *rootPath != "" {
		root, err := os.OpenRoot(*rootPath)
		if err != nil {
			fmt.Fprintln(stderr, "ovpn-inspect: could not open reference root")
			return 1
		}
		defer root.Close()
		opts.Root = root
	}
	cfg, warnings, err := profile.Parse(r, opts)
	for _, warning := range warnings {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Valid profile. Remotes: %d. Remote random: %t.\n", len(cfg.Endpoints), cfg.RemoteRandom)
	return 0
}
