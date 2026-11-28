# Optional connection and host integrations

## TCP proxies

Set `client.Config.Dialer` from `integrations/proxy.HTTPConnect` or
`integrations/proxy.SOCKS5`. Both reuse the normal OpenVPN stream
framing and retain the original server verification policy, including
pins and CRLs. The proxy address, optional TLS roots, and credentials
come from the application. The proxy credentials are independent from
VPN credentials. By default the proxy connection and negotiation share
a ten-second deadline within the client's socket budget.

HTTP uses CONNECT with an optional Basic proxy credential. SOCKS5
uses CONNECT with either the no-authentication method or RFC 1929
username/password. Credentials require verified TLS to the proxy.
`tcp` may delegate destination DNS to the proxy. For `tcp4` or `tcp6`,
specify a literal or configure a family-aware `client.Resolver` to
provide a matching address. UDP ASSOCIATE, HTTP authentication
negotiation, and proxy directives in untrusted profiles are disabled.
Rejected replies, malformed responses, and TLS failures produce
redacted proxy errors. [HTTP CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect) · [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928) · [SOCKS5 authentication](https://www.rfc-editor.org/rfc/rfc1929)

## Session leases and reports

`integrations/sessions.Manager` reserves a unique caller-supplied ID,
one worker, and a configured packet-budget share for each active client.
Admission is immediate with no waiting queue. The aggregate packet
budget is the sum of configured frame ceilings. The core separately
bounds forwarding buffers, protocol queues and dial candidates. Each
lease opens its own packet device and generation callback through a
`DeviceFactory`. The factory must provide independently owned
network state and honor cancellation. The manager closes the device
on partial failures and returns the quota after connecting, forwarding,
and teardown have finished. `Stop` requests cancellation and `Wait`
joins cleanup. Session identifiers are operator labels and must be
chosen without credentials or host names.

`sessions.New` retains the 64-lease limit. Use `sessions.NewWithResources`
to configure a higher limit with an explicit aggregate packet-buffer
estimate and optional file-descriptor budget. Each reservation includes
both receive queues, working packet buffers, UDP scratch, and fragment
reassembly when enabled. `StartWithResources` adds caller-declared
adapter costs. `Usage` includes establishing and closing leases.
The estimate excludes TLS state, goroutine stacks, kernel socket memory
and transient allocations. Size the host from measured process and
kernel resource use.

To bound simultaneous initial attempts, reconnects and TLS rekeys, share
a `client.HandshakeLimiter` through `client.Config`. Each shared limiter
has an independent in-flight limit and FIFO wait queue. Full queues
return `CodeCapacity` from an explicit initial `Connect`. During
automatic recovery, the client counts each admission rejection against
the retry budget, applies the configured jittered backoff, and retries
the same endpoint. Reconnects stay disabled when `DisableReconnect`
is set. Cancellation releases the slot or removes the entry.
Waiting initial attempts use the configured dial timeout, and
rekeys use the existing handshake timeout. Set the queue to cover the
rekeys and recovery burst the deployment can admit. Healthy packet
forwarding uses no admission slot between handshakes.
[Load and reconnect tests](NATIVE_LOAD.md)

`Client.AttemptReports(afterSequence)` returns up to 64 recent completed
attempts with outcome stage, redacted code, timing, endpoint number,
retry reason and connection generation. Under the default dialer,
OS-managed DNS is part of the dial stage. Explicit resolver failures
report the resolve stage. Failed teardown of an unpublished socket
or session sets `AttemptReport.CleanupFailed`, preserves the primary
error and prevents the same client from dialing again. A benign
already-closed result does not trigger the latch.
`Client.GenerationReports(afterGeneration)`
returns up to 64 finished connection generations and the current
snapshot. Counters count successfully forwarded plaintext packets and
bytes. Rekey retains the generation ID. Both histories are safe to
serialize without including endpoint configuration or peer messages.

## Linux network leases

`integrations/hostnet.Controller.Configure` implements
`client.TunnelConfigurer`. Scope each controller to a dedicated,
pre-provisioned interface, a dedicated routing table, and a private
journal directory. Reserve one journal per scope. The trusted policy
allowlists assigned addresses, on-link destination prefixes, resolver
addresses and split DNS domains. Plan fields cannot select the device,
table or binaries. The Linux backend only uses fixed iproute2 commands
for addresses and scoped routes and an optional systemd-resolved
per-link configuration for DNS. Policies and privileged provisioning
belong to the embedding application.

For a service deployment, the VPN worker runs unprivileged with a
pre-opened packet device. Place the controller/backend in a separate
local service with `CAP_NET_ADMIN` in the target network namespace.
Provision routes into that service's table through a host policy rule
owned by the operator. Allow only the needed resolved per-link
authorization if DNS is enabled. Keep a dedicated interface and table
free of resources owned by other processes. A future IPC wrapper
should authenticate the local caller, bind credentials to one
preassigned scope, and expose lease setup and release only. The
repository provides the typed controller and Linux reference backend
for local embedding.

The file journal locks its private directory, syncs intent before any
mutation, and deletes the record after all cleanup succeeds. Run
`Recover` before accepting a lease. It validates journal scope and
policy and removes any owned resources left by a killed process,
including partially applied leases. Rollback uses a separate five-second
cleanup context. A failed cleanup retains the journal and blocks the
next setup. Keep the recovery policy stable until its pending lease has
been removed. The caller closes the journal after stopping its controller.
Linux address and route cleanup has an isolated namespace test. DNS
transaction ordering and failed cleanup are exercised with a simulated
backend. The systemd-resolved backend requires a host running resolved
with per-link permission. [systemd-resolved D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html) · [OpenVPN 3 Linux separation](https://github.com/OpenVPN/openvpn3-linux)

## Native VPN integration evaluation

The supported boundary is `tunnel.PacketConn` for whole IP packets,
`client.TunnelConfigurer` for each authenticated generation, and
`integrations/platform.Run` for native network changes and revocation.
The bridge tears down and joins the previous lease before reopening the
device and transport. Each platform wrapper should use its own signing,
packaging, permission declaration and packet I/O shim.

| Target | Native entry point | Evidence and next qualification |
|---|---|---|
| Linux | TUN, optionally managed by the network lease controller | Packet I/O and routed traffic tested in Linux namespaces. Run a host-specific check for resolved and routing policy integration. |
| Android | `VpnService.Builder`, `ParcelFileDescriptor`, `protect()`, and `ConnectivityManager` network callbacks | Design only. Obtain VPN consent, protect the outer socket before connect, and verify revocation and Wi-Fi/cellular transitions on an authorized device. [Android VPN API](https://developer.android.com/reference/android/net/VpnService) |
| iOS, iPadOS, macOS | Network Extension `NEPacketTunnelProvider`, packet flow, tunnel network settings | Design only. Test a signed extension with the required Network Extension entitlement, cancellation on stop, and transitions between host networks. [Apple Packet Tunnel Provider](https://developer.apple.com/documentation/NetworkExtension/packet-tunnel-provider) |
| Windows | A native VPN plug-in using `Windows.Networking.Vpn.VpnChannel` and the `networkingVpnProvider` capability | Design only. Test with an authorized signed package and VPN profile, including cancellation of blocked packet I/O and network handoff. [Windows VPN namespace](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn) |

The portable bridge is tested with synthetic devices and network-change
notifications. A native prototype should use isolated credentials and
measure socket exclusion from the tunnel, authenticated traffic before
and after a network change, removal of generation settings after
cancellation, and bounded shutdown during an OS-initiated revoke.
