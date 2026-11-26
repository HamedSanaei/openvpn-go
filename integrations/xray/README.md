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
addresses and routes. The tested Xray data-path example uses IPv4.

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

Domain routing needs a separately configured DNS path through the
tunnel. The example blocks unmatched targets and uses the normal
Xray socket bind failure as an outbound error. Review that the
`via-vpn` inbound and its matches precede other fallback rules.

Send SIGTERM to the adapter to cancel dial, backoff and forwarding.
The command closes its TUN handle after the client joins its workers.
The host owns the persistent device, routes and Xray process. To change
the host or peer address assignment, update the device and restart the
adapter with matching expected addresses.

## Verify

The isolated test runs stock Xray with the example outbound, sends TCP
and UDP through OpenVPN to an echo process in a second network
namespace, restarts the OpenVPN peer and checks both protocols again.
See the [integration test](../../tests/interop/xray_test.go) and
[interop commands](../../tests/interop/README.md).
