package main

import (
	"encoding/json"
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
	capabilities := flags.Bool("capabilities", false, "print a redacted directive report")
	authPath := flags.String("auth-file", "", "two-line OpenVPN credential file")
	protonName := flags.String("protonvpn-server-name", "", "trusted exact Proton VPN certificate name")
	passwordOnly := flags.Bool("allow-password-only", false, "allow verified profiles without a client certificate")
	err := flags.Parse(args)
	if err != nil || flags.NArg() != 1 {
		if err == flag.ErrHelp {
			fmt.Fprintln(stdout, "Usage: ovpn-inspect [-capabilities] [-root directory] [-allow-password-only] [-auth-file path] [-protonvpn-server-name name] profile.ovpn|-")
			return 0
		}
		fmt.Fprintln(stderr, "Usage: ovpn-inspect [-capabilities] [-root directory] [-allow-password-only] [-auth-file path] [-protonvpn-server-name name] profile.ovpn|-")
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
	opts := profile.Options{AllowPasswordOnly: *passwordOnly, ProtonVPNServerName: *protonName}
	if *capabilities {
		report, err := profile.InspectWithOptions(r, opts)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			return 1
		}
		for _, entry := range report.Entries {
			if entry.Capability == profile.Rejected || entry.Capability == profile.PolicyDisabled {
				return 1
			}
		}
		return 0
	}
	if *authPath != "" {
		opts.Credentials, err = profile.ReadCredentialsFile(*authPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
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
