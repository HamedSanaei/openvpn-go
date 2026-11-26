# Xray egress on Linux

`ovpn-xray` connects a provisioned Linux IP TUN to the OpenVPN client.
3x-ui adds a standard Xray `freedom` outbound bound to that interface.
This lets Xray use the tunnel for selected TCP and UDP flows while the
OpenVPN peer socket follows the host's ordinary route.

The target is 3x-ui `e50f949a04174e26de247b40baa2e260415174e9` and its
stock Xray-core 26.10.21 build. The adapter is a separate binary, with no
Xray library in the main Go module. [Boundary and pin](../../docs/adr/0007-xray-linux-egress.md)

## Provision the Linux host

Use the tunnel address guaranteed by your OpenVPN configuration. The
following example provisions IPv4 `10.49.0.2`, device `ovpn0` and routing
table `400`. Choose an unused routing table and rule priority. Provision
the TUN for the same local account that runs the adapter.

~~~sh
sudo ip tuntap add dev ovpn0 mode tun user "$USER"
sudo ip address add 10.49.0.2/32 dev ovpn0
sudo ip link set ovpn0 mtu 1400 up
sudo ip route add default dev ovpn0 src 10.49.0.2 table 400
sudo ip rule add priority 10400 oif ovpn0 lookup 400
~~~

Provide the trusted CA, client certificate and key in a supported
profile. Credentials may be inline or referenced under `-root`.
Use `-allow-password-only` for a profile with verified server trust
and explicit `auth-user-pass` that omits both client identity fields.
Use service-account-readable permissions for these files. The device's
addresses must match the negotiated addresses. Provision the same
addresses on each eligible peer for recovery across remotes.

~~~sh
ovpn-inspect -root /etc/openvpn/material /etc/openvpn/client.ovpn
ovpn-xray -profile /etc/openvpn/client.ovpn -root /etc/openvpn/material \
  -tun ovpn0 -ipv4 10.49.0.2
~~~

`-attempts=-1` opts in to unlimited cancellable retries. Otherwise
the default recovery budget visits every profile candidate once.
Use `-ipv6` with the expected host prefix when you also provision IPv6
addresses and routes.

## Configure 3x-ui

Add the [outbound JSON](openvpn-outbound.json) to the Xray template's
`outbounds`. Route the intended inbound to `openvpn`. For an IPv4-only
example with literal destinations, retain `routing.domainStrategy`
as `AsIs` and place these rules ahead of broader matches. Use a
`blackhole` outbound tagged `ovpn-blocked` for the second rule.

~~~json
[
  {
    "type": "field",
    "inboundTag": ["via-vpn"],
    "ip": ["0.0.0.0/0"],
    "outboundTag": "openvpn"
  },
  {
    "type": "field",
    "inboundTag": ["via-vpn"],
    "outboundTag": "ovpn-blocked"
  }
]
~~~

### IPv6 and DNS inside the tunnel

For a dual-stack peer, provision the assigned IPv6 prefix and routing
policy for `ovpn0`. Add `-ipv6 fd49:67::1000/64` to the adapter command
when using the test prefix below.

~~~sh
sudo ip -6 address add fd49:67::1000/64 dev ovpn0 noprefixroute
sudo ip -6 route add default dev ovpn0 src fd49:67::1000 table 400
sudo ip -6 rule add priority 10400 oif ovpn0 lookup 400
~~~

Set the Xray resolver to an address and port reachable inside your VPN.
This example resolves names to IPv6 and routes the resolver's UDP traffic
through the same interface as the selected application inbound. Merge the
objects into the corresponding sections of the Xray template.

~~~json
{
  "dns": {
    "tag": "vpn-dns",
    "queryStrategy": "UseIPv6",
    "disableFallback": true,
    "servers": [{"address": "10.49.0.1", "port": 53}]
  },
  "outbounds": [
    {"tag": "ovpn-blocked", "protocol": "blackhole"},
    {
      "tag": "openvpn",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {"interface": "ovpn0", "domainStrategy": "ForceIPv6"}
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["via-vpn", "vpn-dns"],
        "outboundTag": "openvpn"
      }
    ]
  }
}
~~~

`ForceIPv6` makes DNS failure terminal for domain destinations. Put the
VPN rule above broader matches. A dedicated Xray instance can use
`ovpn-blocked` as the default outbound to drop unmapped flows. In a shared
instance, keep the existing default for unrelated inbounds and ensure both
VPN tags always match the VPN rule. An unavailable interface fails the
socket setup.
[Xray socket options](https://xtls.github.io/en/config/transports/sockopt.html) · [Xray DNS](https://xtls.github.io/en/config/dns.html)

### Lifecycle

Send SIGTERM to the adapter to cancel dial, backoff and forwarding.
The command closes its TUN handle after the client joins its workers.
The host owns the persistent device, routes and Xray process. To change
the host or peer address assignment, update the device and restart the
adapter with matching expected addresses.

Applications embedding the Go adapter can instead use
`xray.NewConfigured` to prepare and roll back changed assignments on
the same caller-owned device. The application resolver can consume the
authenticated DNS groups with `ActiveDNS` and open generation-bound
sockets using `DialDNS` with `BindDNSDevice`. Configure Xray itself to
send resolver traffic through that intended path.
[Transaction and DNS contract](../../docs/TUNNEL.md)

## Verify

The isolated stock Xray test sends concurrent TCP and UDP requests to
IPv4 literals, IPv6 literals and an AAAA name from an in-tunnel resolver.
It repeats the six flows after restarting OpenVPN. Reachable loopback
listeners detect unwanted fallback after DNS failure or an unavailable
bound interface.
See the [integration test](../../tests/interop/xray_test.go) and
[interop commands](../../tests/interop/README.md).
