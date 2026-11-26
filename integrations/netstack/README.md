# Unprivileged userspace networking

This optional Go module lets an application use TCP, UDP and DNS through
its OpenVPN client without provisioning an OS TUN, modifying routes or
requiring administrator permissions. Each adapter has its own gVisor
TCP/IP stack, so independent VPN sessions can use the same addresses and
ports. The OpenVPN peer transport still uses the application's regular
OpenVPN dialer.

The module requires Go 1.27.4 and builds with `CGO_ENABLED=0`. Its
dependencies are confined to this module.
[Dependency provenance](../../docs/PROVENANCE.md#optional-userspace-module)

## Attach an adapter

Connect the OpenVPN client and read its authenticated `ControlInfo`.
Use the valid assigned IPv4 and IPv6 prefixes in `ControlInfo.Tunnel`.
Keep their assigned host addresses and use the agreed MTU if present.
Choose DNS endpoints from your application policy.

~~~go
adapter, err := netstack.New(netstack.Config{
	Addresses:  []netip.Prefix{info.Tunnel.IPv4},
	DNSServers: []netip.AddrPort{netip.MustParseAddrPort("10.49.0.1:53")},
	MTU:        uint32(info.Tunnel.MTU),
	MaxSockets: 32,
})
if err != nil {
	return err
}
defer adapter.Close()
~~~

This example assumes the authenticated session assigned an IPv4 address
and the application's approved resolver is `10.49.0.1:53`. The adapter
satisfies `tunnel.PacketConn`. Run the connected client with the adapter
in a worker using `Client.Run` or `Client.RunConfigured`. For reconnects,
use `RunConfigured` and verify the new generation still matches the
stack's address and MTU settings before permitting forwarding. Cancel
and join the worker before disposing of the client and adapter. Create a
fresh adapter for a new assignment or resolver policy.

Use `adapter.DialContext(ctx, "tcp", "10.49.0.1:443")` or the `"udp"`
variant for numeric addresses. The context bounds socket setup, with a
ten-second cap. Set per-socket read and write deadlines for application
traffic and close each connection when finished. The default is 64
simultaneous sockets, configurable up to 256 per adapter. The maximum
queued outbound IP packets is 64.

`ExchangeDNS(ctx, server, query)` sends one DNS wire query to a configured
numeric endpoint with a five-second cap. It supports bounded UDP replies
and retries a truncated reply over TCP to the same endpoint. The caller
supplies and interprets the DNS message, including question and answer
policy. The adapter performs no system resolution.

## Verify

Run these commands from `integrations/netstack`. The local lab uses two
parallel in-memory VPN packet links with overlapping addresses and
distinct payloads. It checks TCP, UDP and DNS, the socket limit, and
cancellation during a blocked dial and packet read.

~~~sh
go mod verify
CGO_ENABLED=0 go test ./...
go test -race ./...
~~~
