# Authenticated tunnel and DNS configuration

`client.ControlInfo().Tunnel` contains the peer's authenticated tunnel
configuration. The IPv4 and IPv6 prefixes preserve the assigned host
address. The snapshot supplies topology, point-to-point peers, default
VPN gateways, canonical routes with optional metrics and a pushed MTU.
`Routes()` and `DNS()` return detached copies. An unset field has no
value from the peer or was ignored by policy. Route entries with an
unset gateway use the VPN gateway for that family. The embedding
application owns interface addresses, routes, DNS and privileges.
A packet discarded by a short local read, rejected by the effective MTU
or malformed on local input is a packet-local drop. Adapters can return
`tunnel.ErrMTUExceeded` or an error implementing `MTUExceeded() bool`.
The caller may inspect `Client.Stats` for packet drops and separate
bounded queue counters. `CiphertextQueue` counts DATA_V2 frames before
authentication. `InboundQueue` counts complete authenticated IP
packets. Each shows lifetime drops and an observed maximum occupancy.
Full queues discard new arrivals without holding up control traffic.

## Push policy

Set `client.Config.PushPolicy` to control four classes. Each class
defaults to `tunnel.PushAccept`. Choose `tunnel.PushIgnore` to omit its
metadata or `tunnel.PushReject` to reject the session when the peer sends
a directive in that class. The policy applies to authenticated pushes.
Unknown directives and unsupported protocol/security options still fail
negotiation. Malformed and duplicate accepted settings fail with a
redacted protocol error. Settings across continued replies are validated
together before publication.

| Class | Accepted metadata |
| --- | --- |
| Addresses | `topology`, `ifconfig`, `ifconfig-ipv6`; `tun-ipv6` is a compatibility hint. |
| Routes | `route`, `route-ipv6`, `route-gateway`, `route-ipv6-gateway`. Use numeric gateways or the default VPN gateway on a route. `redirect-gateway` is recognized as an advisory OS operation and has no metadata effect. |
| MTU | `tun-mtu` from 68 to 65535. When IPv6 is assigned, the minimum is 1280. The application sets its device MTU and selects a client packet-size limit that accommodates it. |
| DNS | Numeric `dhcp-option DNS` and `DNS6`, `DOMAIN`, `ADAPTER_DOMAIN_SUFFIX` and `DOMAIN-SEARCH`, plus `dns search-domains` and indexed `dns server` settings. Validated legacy hints `WINS`, `NBDD`, `NTP`, `NBT`, `NBT-SCOPE`, `DISABLE-NBT` and `block-outside-dns` have no host effect. Unknown suboptions fail under the accepting policy. |

Authenticated `socket-flags TCP_NODELAY`, numeric `sndbuf` and `rcvbuf`
are validated transport hints. Socket flags and buffer sizes are owned by
the dialer. The optional legacy `explicit-exit-notify` retry count is
validated, and reliable exit notification still depends on the
authenticated `cc-exit` protocol flag.

Applications that apply authenticated DNS metadata may set
`client.Config.AdvertiseDNS` with `PushAccept`. This advertises the
OpenVPN 2.6 DNS option bit. The later DNS v2 bit remains unadvertised
until its distinct grammar is supported. DNS and routing enforcement
belong to the adapter.

DNS groups are ordered by index and each group can supply multiple
IPv4/IPv6 endpoints, split domains, transport, DNSSEC mode and a TLS
server name. Indexed server addresses replace legacy DHCP DNS addresses.
Modern search domains replace the legacy search list when supplied.
Numeric ports are normalized to 53 for plain DNS, 853 for DoT and 443
for DoH when the peer omits them. Limits are 128 routes, 16 DNS groups,
8 addresses per group and 10 domains per domain list. DNSSEC,
DoT/DoH certificate policy, split-domain selection and query processing
belong to the application resolver.
[OpenVPN 2.6 push and DNS documentation](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)

## Transactional reconnect

Call `Client.RunConfigured(ctx, device, configure)` after `Connect` when
the application needs to acknowledge settings. `configure` receives a
generation number, the authenticated endpoint and control information.
It runs serially for every initial or recovered connection. Rekey keeps
the generation unchanged. Apply the interface and resolver state in
the callback, then return the restore function and a nil error to permit
packet forwarding. Return the restore function with an error if setup
partially changes state and must be rolled back.

On disconnect, cancellation or failure, the client cancels the
generation context, joins the packet workers and runs the restore
function exactly once before trying another connection. Configuration
rejection stops forwarding and returns a redacted tunnel error.
Callbacks should honor cancellation and release their changes promptly.
The application retains ownership of the packet device. A connected
control session can be observed before configuration is acknowledged.

## Xray adapter

The Go embedding entry point `xray.NewConfigured` takes the same
transactional callback. Fixed IPv6 addresses require an MSS MTU of at
least 1280 when clamping is enabled. Supply `xray.BindDNSDevice(deviceName)` on Linux
as the DNS dialer to require socket binding to a caller-provisioned VPN
interface. A custom dialer must enforce the same route binding and
cancellation contract.

An application resolver calls `ActiveDNS()` to get the acknowledged
generation number and a snapshot of allowed DNS groups, selects a server
for the query domain and passes the number and numeric endpoint to
`DialDNS`. A stale generation, a pending configuration, an unauthorized
endpoint or failed binding returns an error. An authorized caller's
deadline or cancellation is returned directly, including when a dial
is interrupted during generation retirement. Use TCP for DoT and DoH
and apply the advertised resolver policy in the calling application.
The adapter closes generation-owned DNS sockets before restoring the old
configuration. It never consults the host resolver.
[Xray integration](../integrations/xray/README.md)
