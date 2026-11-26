package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/hamedsanaei/openvpn-go/integrations/xray"
	"github.com/hamedsanaei/openvpn-go/profile"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	status := run(ctx, os.Args[1:], os.Stderr)
	stop()
	os.Exit(status)
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("ovpn-xray", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("profile", "", "client OVPN profile")
	rootPath := flags.String("root", "", "authorized directory for profile references")
	tun := flags.String("tun", "", "existing Linux TUN device")
	v4 := flags.String("ipv4", "", "expected IPv4 address")
	v6 := flags.String("ipv6", "", "expected IPv6 address and prefix")
	attempts := flags.Int("attempts", 0, "maximum dial attempts per sequence")
	mssMTU := flags.Int("mss-mtu", 0, "inner MTU ceiling for optional TCP MSS clamping")
	authPath := flags.String("auth-file", "", "two-line OpenVPN credential file")
	protonName := flags.String("protonvpn-server-name", "", "trusted exact Proton VPN certificate name")
	passwordOnly := flags.Bool("allow-password-only", false, "allow verified profiles without a client certificate")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" || *tun == "" || (*v4 == "" && *v6 == "") {
		fmt.Fprintln(stderr, "Usage: ovpn-xray -profile client.ovpn -tun ovpn0 [-root directory] [-ipv4 addr] [-ipv6 prefix] [-attempts n] [-mss-mtu n] [-allow-password-only] [-auth-file path] [-protonvpn-server-name name]")
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	var addresses xray.Addresses
	var err error
	if *v4 != "" {
		addresses.IPv4, err = netip.ParseAddr(*v4)
		if err != nil {
			fmt.Fprintln(stderr, xray.ErrTunnelConfig)
			return 2
		}
	}
	if *v6 != "" {
		addresses.IPv6, err = netip.ParsePrefix(*v6)
		if err != nil {
			fmt.Fprintln(stderr, xray.ErrTunnelConfig)
			return 2
		}
	}
	opts := profile.Options{AllowPasswordOnly: *passwordOnly, ProtonVPNServerName: *protonName}
	if *authPath != "" {
		opts.Credentials, err = profile.ReadCredentialsFile(*authPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if *rootPath != "" {
		opts.Root, err = os.OpenRoot(*rootPath)
		if err != nil {
			fmt.Fprintln(stderr, "ovpn-xray: could not open the authorized reference root")
			return 1
		}
		defer opts.Root.Close()
	}
	file, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(stderr, "ovpn-xray: could not open profile")
		return 1
	}
	cfg, warnings, err := profile.Parse(file, opts)
	file.Close()
	for _, warning := range warnings {
		fmt.Fprintln(stderr, "warning:", warning)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "attempts" {
			cfg.Retry.MaxAttempts = *attempts
		}
	})
	device, err := xray.OpenDevice(*tun, addresses)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer device.Close()
	adapter, err := xray.NewFixed(cfg, device, addresses, xray.Options{MSSMTU: *mssMTU})
	if err == nil {
		err = adapter.Run(ctx)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
