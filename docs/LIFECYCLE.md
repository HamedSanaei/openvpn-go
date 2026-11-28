# Failover and reconnect

`client.New` creates a fixed attempt order from the declared endpoints.
`RemoteRandom` shuffles that order once and preserves every candidate.
An endpoint's address family, transport, expected certificate identity,
SNI and control protection travel together through every attempt.
Remote socket targets must be unicast. Literal and resolved IPv4 limited
broadcast addresses are rejected, including IPv4-mapped representations.

`Connect(ctx)` tries the first candidate immediately. A failed recoverable
attempt advances to the next candidate and waits through backoff. The
attempt order wraps if the budget allows. A successful connection requires
verified TLS and negotiated data keys. The resulting session has its own
lifetime.

## Retry policy

Configure recovery through `client.Config.Retry` before calling `client.New`.

| Field | Behavior |
|---|---|
| `MaxAttempts` | Zero gives one pass through the endpoints per sequence. Use 1–1,024 for an explicit attempt count or `client.UnlimitedAttempts` for a cancellable unlimited sequence. |
| `InitialBackoff` | First retry delay ceiling, 250 ms by default. |
| `MaxBackoff` | Maximum delay ceiling, 10 seconds by default or the initial ceiling if it is larger. Configurable ceilings range from 1 ms to 5 minutes. |
| `DisableReconnect` | Return from `Run` when the active session ends. Initial `Connect` still uses the configured failover policy. |

Each failure doubles the delay ceiling up to the cap. Jitter samples
uniformly between half the current ceiling and the ceiling. Each attempt
has independent dial and handshake limits of 10 and 60 seconds by default.
`ConnectTimeout` allows up to two minutes and `HandshakeTimeout` allows up
to five minutes. The enclosing operation context can end either stage sooner.

Transport I/O failure, retransmission exhaustion, timeout and authenticated
peer restart can trigger recovery. Certificate, authentication, protocol,
protection configuration and tunnel errors terminate the operation.
An authenticated `HALT` or `EXIT` terminates the sequence. A restart that
requests credential purging returns an authentication error so the caller
can supply fresh credentials. Control messages and their text stay inside
the TLS session.

## Forwarding and shutdown

After `Connect` succeeds, start `Run(ctx, device)` to forward packets.
`Run` owns recovery while forwarding is active. On a recoverable loss it
joins the old forwarding workers, closes the old session and tries the
next candidate after the initial backoff. An authenticated `RESTART,[N]`
on the established session starts recovery at the same endpoint. Success
resets the retry budget and resumes forwarding through the same borrowed
device. In-flight packets from the failed session are discarded.

Each successful handshake creates fresh control state and data keys. An
auth token is scoped to the session that received it, including its rekeys.
During promotion, a terminal decision dispatched by the authenticated
control link retains authority even if the replacement is already ready.
Retirement ends that authority. Ordinary closure of a retiring control
stream lets the pending exchange complete.
Another session uses the credentials supplied to `client.New`. The embedding
application owns the device and its addresses and routes. Read `ControlInfo`
after a connection event to obtain the newly negotiated tunnel settings.
Between forwarding runs, `Connect` starts a new attempt sequence.

Adapters using `RunConfigured` acknowledge each authenticated generation
before forwarding starts. A rejected change is rolled back and stops the
session. On recovery the old rollback completes before the next
configuration callback runs. [Tunnel callback contract](TUNNEL.md#transactional-reconnect)

Cancel `Connect` or `Run` to stop the corresponding operation. `Close`
permanently stops the client, interrupts waits and joins active operations.
The embedding application closes the borrowed device.

If the session ends between a successful `Connect` and the first
`RunConfigured` or `Run`, forwarding uses the ordinary recovery policy.
The caller can read state or statistics in between. Those reads can finish
accounting for the ended generation while retaining its redacted cause.
An explicit new `Connect` starts a fresh attempt sequence.

## Custom packet transports and proxy streams

Set `Config.Dialer` to a `transport.Dialer` when the adapter already handles
packet I/O. For a connected proxy stream, use
`transport.SocketDialer{MaxPacketSize: limit}.WithDialContext(dial)`
to reuse OpenVPN framing. The hook receives the original remote network
and address. TCP needs a reliable byte stream and UDP needs datagrams.
Adapters must honor cancellation and packet size limits. A returned packet
connection transfers ownership to the client, and a completed TLS session
takes ownership of that connection. The destination's configured identity
is still the identity verified by TLS.

## Events and statistics

`State`, `ActiveEndpoint` and `ControlInfo` report the current session.
`StateBackoff` indicates a scheduled retry. `Stats` exposes aggregate attempt,
connection, recovery and traffic counters. Its active endpoint index refers
to the original configured list, with `-1` when no session is active.
Traffic counters count packets successfully forwarded and their plaintext
byte totals in each direction.

`Events(afterSequence)` returns a copy of up to 64 recent events. Begin
with sequence zero and use the last event's sequence to read newer
entries. A sequence gap indicates that older entries were overwritten.
Events carry only time, sequence, event kind, endpoint index, error code
and delay. Callers can record these fields in their own logs.

[Architecture](ARCHITECTURE.md#m5-lifecycle) · [Security model](SECURITY_MODEL.md) · [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [OpenVPN wire draft §8.6](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-8.6)
