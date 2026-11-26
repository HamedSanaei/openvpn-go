# OpenVPN profiles

Use `profile.Parse` to validate an OVPN profile and prepare a
`client.Config` for `client.New`. Both calls run before any network
connection. The embedding application owns the reader and any `os.Root`.
It can set a custom dialer or change an endpoint's expected TLS server
name before constructing the client.

~~~go
func loadProfile(path string) (*client.Client, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    cfg, warnings, err := profile.Parse(file, profile.Options{})
    for _, warning := range warnings {
        log.Print(warning)
    }
    if err != nil {
        return nil, err
    }
    return client.New(cfg)
}
~~~

The inspection command prints a redacted summary and line-numbered warnings.
A dash reads the profile from standard input. An explicit root authorizes
file references.

~~~sh
go run ./cmd/ovpn-inspect client.ovpn
go run ./cmd/ovpn-inspect -root ./materials client.ovpn
go run ./cmd/ovpn-inspect -capabilities client.ovpn
~~~

`profile.Inspect` and `ovpn-inspect -capabilities` enumerate directive
capabilities before parsing material. The report uses stable
`supported`, `ignored`, `rejected` and `policy-disabled` values and
one-based line numbers. Unknown names and all raw arguments stay out
of the report. A rejected inline block is skipped as material. A block
without a matching close consumes its remaining body. The JSON command
returns a failing exit status for rejected or disabled entries. Use
`Parse` to check required directives and load authorized material afterward.

## Directive registry

Use one directive per line. The parser supports UTF-8, an optional BOM,
LF and CRLF, single or double quoted arguments and OpenVPN backslash
escaping outside single quotes. A leading `--` is optional. A `#` or
`;` at an argument boundary starts a comment. Inline block tags occupy
their own lines.

| Directive | Accepted arguments and behavior |
|---|---|
| `client` | Enables TLS client mode and authenticated push. |
| `tls-client`, `pull` | Together equivalent to `client`. |
| `dev` | `tun` or a numbered TUN name such as `tun0`. The embedding application supplies the tunnel. |
| `dev-type` | Optional explicit `tun`. |
| `remote` | `host [port [proto]]`. Use a DNS name or an unbracketed IP address and a numeric port from 1 to 65535. |
| `<connection>` | Contains exactly one `remote` and optional connection settings. |
| `proto` | `udp`, `udp4`, `udp6`, `tcp`, `tcp4`, `tcp6`, or `tcp-client`, `tcp4-client`, `tcp6-client`. |
| `port`, `rport` | Numeric remote port from 1 to 65535. With `bind`, `port` also sets the default source port. |
| `remote-random` | Shuffle the complete list once at `client.New`. `profile.Parse` returns declared order. |
| `ca` | Relative PEM certificate bundle path or `<ca>` block. Required. |
| `cert` | Relative PEM client certificate chain path or `<cert>` block. Required with `key`, except when password-only authentication is explicitly authorized. |
| `key` | Relative PEM client private key path or `<key>` block. The unencrypted key must match the certificate. Omit it when the caller supplies `profile.Options.Identity`. |
| `auth-user-pass` | Relative path, `<auth-user-pass>` block, or bare directive with `profile.Options.Credentials` or `profile.Options.Authentication.Credentials`. Material contains exactly the username and password on separate lines. Their surrounding spaces are preserved. |
| `auth-nocache` | With `auth-user-pass`, requires bare `auth-user-pass` and a caller credential callback. The client retains no callback password between handshakes. |
| `tls-auth` | Relative Static Key V1 path with optional direction `0` or `1`, or `<tls-auth>` block. |
| `tls-crypt` | Relative Static Key V1 path or `<tls-crypt>` block. |
| `tls-crypt-v2` | Relative wrapped client PEM key path or `<tls-crypt-v2>` block. |
| `key-direction` | `0` or `1` for `tls-auth`. Omission allows bidirectional mode. Both forms must agree when supplied together. |
| `auth` | `SHA1`, `SHA256`, `SHA384` or `SHA512`, case-insensitive. Selects the OpenVPN auth digest, including the HMAC for `tls-auth`. The default is `SHA1`. |
| `data-ciphers` | Ordered, colon-separated subset of `AES-256-GCM`, `AES-128-GCM` and `CHACHA20-POLY1305`, with each cipher listed at most once. Omission offers all three. |
| `cipher` | A single supported AEAD produces an `ignored_directive` warning. Configure the negotiated offer with `data-ciphers`. |
| `compat-fixed-aead` | Explicit fixed `AES-128-GCM` or `AES-256-GCM` for one remote. Selects the concise server key-method-2 reply, classic derivation and DATA_V2 for that endpoint. Requires a client certificate and plain outer control with verified TLS. |
| `remote-cert-tls` | `server`. Requires explicit leaf Key Usage and TLS server Extended Key Usage. |
| `peer-fingerprint` | SHA-256 leaf fingerprint with 32 colon-separated hex octets, a relative file path, or an inline block with one fingerprint per line. Up to 32 distinct pins are accepted across all declarations. |
| `crl-verify` | Relative file path or inline block containing PEM X.509 CRLs in complete issuer list format. |
| `verify-x509-name` | `value [subject\|name\|name-prefix]`, with `subject` as the default. See identity policy below. |
| `tls-version-min` | `1.2` or `1.3`, optionally followed by `or-highest` on a recognized version. Defaults to TLS 1.2. |
| `tls-version-max` | `1.2` or `1.3`. Defaults to TLS 1.3. |
| `allow-compression` | `no`. |
| `nobind` | Requests the default ephemeral local socket. |
| `bind`, `local`, `lport` | Bind the built-in socket. `local` accepts an IP literal and `lport` a numeric source port. Explicit `bind` uses source port 1194 if neither `lport` nor `port` sets it. Binding conflicts with `nobind` in the same scope. |
| `disable-dco` | Requests the standard userspace data path. |
| `persist-key`, `persist-tun` | Accepted with an `ignored_directive` warning. The library owns session keys and the caller manages the tunnel. |
| `resolv-retry` | DNS retry budget of 0–120 seconds. Each dial has its own deadline. `infinite` retries DNS until that deadline or cancellation. |
| `connect-timeout` | Dial deadline in seconds, 1–120. |
| `connect-retry` | Initial and optional maximum retry delay ceilings in seconds, 1–300. Uses the client retry policy's jitter. |
| `connect-retry-max` | Number of visits per remote in rotating order. The total per sequence must be at most 1024. |
| `hand-window` | Initial TLS/control deadline and rekey deadline in seconds, 1–300. |
| `reneg-sec` | Client timer-driven rekey interval in seconds, 1–86400. Zero disables the timer. The key usage limit and peer resets still trigger rekey. |
| `explicit-exit-notify` | Optional count from 0–255, default 1. A positive value enables authenticated exit on a capable UDP peer when the application calls `Close`. The count applies to legacy OpenVPN data-channel retransmissions. This client uses the reliable control channel. |
| `tun-mtu` | Inner IP packet ceiling, 68–65535 bytes. See the packet size policy. |
| `verb` | Levels 0 through 11. Reports `ignored_directive`. |

Every other directive is a fatal error. This includes server mode, static-key
mode, compression and compression framing, cipher fallback, executable
hooks, includes, external verification mechanisms and options that alter
the security policy. Known directive names, such as `compress` and
`data-ciphers-fallback`, appear in the diagnostic. An unknown token is
represented by its line and the `unsupported_directive` code.

## Representative exports

| Profile | Directive inventory and security impact |
|---|---|
| OpenVPN Community 2.6 client example | Remote selection, `resolv-retry` and `nobind` affect connectivity. `persist-key`, `persist-tun` and `verb` are lifecycle and logging hints. CA, client identity, `remote-cert-tls` and optional `tls-auth` affect trust. Commented proxy, privilege and legacy cipher examples are outside the profile policy. [Community example](https://github.com/OpenVPN/openvpn/blob/v2.6.23/sample/sample-config-files/client.conf) |
| Access Server 3.2.4 auto-login and user-locked exports | The lab exports use inline CA, client identity and `tls-crypt-v2`, with TLS 1.3. User-locked includes `auth-user-pass`. These alter credential and control protection policy. The observed legacy `cipher AES-256-CBC` declaration is rejected by the AEAD-only parser. [OpenVPN export types](https://openvpn.net/as-docs/v3/using-the-client-web-ui/) · [Lab observations](EXTERNAL_INTEROP.md#provider-and-access-server-profiles) |
| OpenVPN connection-block examples | Ports, protocol, bind, timeout and retry control endpoint selection. `tun-mtu` and `explicit-exit-notify` control packet sizing and teardown. Control-key directives and key direction remain security-sensitive and are validated for each endpoint. `connect-retry` and `connect-retry-max` configure the client-wide policy in this parser. [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) |

## Remote precedence

With top-level `remote` entries, final `proto`, `port` and `rport` values
set defaults. Explicit `remote` arguments override them. With connection
blocks, each block inherits the defaults at its opening, including control
protection. Inside the block, process `remote`, `proto`, `port` and `rport`
in order. Later settings override earlier settings for the same field.
The supported block directives are `remote`, `proto`, `port`, `rport`,
`bind`, `nobind`, `local`, `lport`, `connect-timeout`, `tun-mtu`,
`explicit-exit-notify`, `key-direction`, `tls-auth`, `tls-crypt` and
`tls-crypt-v2`. A `compat-fixed-aead` entry may be declared once inside
each applicable connection block. At top level it requires exactly one
top-level remote and no connection blocks. An explicit `data-ciphers`
offer must contain just the matching cipher. The legacy `cipher`
directive remains advisory. [Fixed AEAD policy](adr/0009-fixed-aead-compatibility.md)
A block's protection replaces its inherited protection. Conflicting modes
within the same scope are errors. Empty or nested connection blocks and
profiles combining block and top-level remotes are errors. Defaults are
UDP and port 1194. Address-family constraints also apply to IP literals.

`client.New` keeps all candidates, with their verification policies and
control keys attached when `remote-random` reorders them. `Connect`
starts at the first candidate and advances on recoverable failure.
Applications configure the retry budget through `client.Config.Retry`.
[Failover and reconnect](LIFECYCLE.md) · [Resolution and packet size policy](CONNECTION_POLICIES.md)

## Identity and material

Trust comes from the profile's `ca` bundle. The default server identity
comes from the configured remote's DNS or IP SAN. A caller can override
that value using `Endpoint.ServerName`. An exact `name` matches one
unambiguous subject common name. An exact `subject` matches the complete
certificate DN in certificate order, for example
`verify-x509-name 'C=US, O=Example VPN, CN=vpn.example.test' subject`.
Use one string attribute per RDN. Common OpenSSL attribute names and
decimal OIDs are accepted. Escape literal commas, plus signs, equal signs
and backslashes with a backslash inside single quotes. A `name-prefix`
checks both the common-name prefix and the normal DNS or IP SAN. All
policies require a valid chain and server TLS purpose.
[Pinning, CRLs and external authentication](CONNECTION_POLICIES.md)

Set `profile.Options.AllowPasswordOnly` together with an
`auth-user-pass` directive to authorize a profile that omits both
`cert` and `key`. The peer must allow password authentication without a
client certificate. `ovpn-inspect` and `ovpn-xray` expose the
`-allow-password-only` switch. Direct Go clients can set
`client.TLSConfig.AllowPasswordOnly` with valid `client.Credentials`.
A single identity field is invalid in either mode. The verified
server CA and identity checks still apply.
[OpenVPN password authentication](https://openvpn.net/community-docs/using-alternative-authentication-methods/)

Use inline material for a standalone profile. For references, supply
`profile.Options.Root` with an `os.OpenRoot` handle to an authorized
material directory, or `profile.Options.Resolver` to open preauthorized
files under equivalent confinement. References use relative paths.
The parser rejects traversal, absolute, drive, UNC and device references,
symlink escapes and non-regular files. Use a root dedicated to profile
material and under the caller's control. The caller owns confinement and
prompt reads when providing a custom resolver.

Profiles and aggregate referenced material are each limited to 1 MiB.
The maximum line length is 64 KiB and the maximum remote count is 64.
Credentials allow up to 4,095 bytes per field. `profile.Diagnostic`
reports a stable code and a one-based line number, or line zero for a
profile-wide error. Fatal failures return a zero configuration. Errors and
warnings omit raw tokens, paths, credentials and key material.

[OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Security requirements](SECURITY_MODEL.md) · [Parser tests](../profile/parse_test.go)

## Proton VPN manual exports

Pass the original export to the application's profile parser with
`Options.ProtonVPNServerName` and `Options.AllowPasswordOnly` set.
Provision the exact certificate common name from independently trusted
provider information, such as a provider-owned DNS name whose A records
include the configured IPv4 remote. The client checks that exact name,
the exported CA and the server certificate purpose. Supply the separate
OpenVPN credentials through `Options.Credentials` or the application
credential callback. The profile must have a bare `auth-user-pass` line.

~~~sh
ovpn-inspect -protonvpn-server-name "$VPN_SERVER_NAME" \
  -allow-password-only -auth-file "$VPN_AUTH_FILE" "$VPN_PROFILE"
~~~

For a service with a provisioned tunnel address, pass the same three
options to `ovpn-xray` alongside the profile and its ordinary TUN
arguments. Applications that configure a fresh TUN address per session
can use the authenticated generation's tunnel configuration.
Keep the credentials file outside version control. The file has a
username on the first line and a password on the second.

| Option in the export | Proton VPN import policy |
|---|---|
| `setenv CLIENT_CERT 0` | Records an ignored hint. The application must still enable password-only authentication explicitly. |
| `mssfix 0` | Records an ignored request to leave MSS adjustment disabled. Nonzero values are rejected. |
| `tun-mtu` | Uses the existing validated per-endpoint MTU policy. |
| `reneg-sec 0` | Uses the existing policy for explicitly disabling timer-driven client rekeys. Peer rekeys and key-usage limits stay active. |
| `block-outside-dns` | Records an ignored Windows-specific hint. The application owns DNS routing and leak prevention. |
| `script-security 2` and the exact `up` and `down` invocations of `/etc/openvpn/update-resolv-conf` | Records the complete three-line group as ignored hints. Other scripts, arguments, paths or incomplete groups are rejected. Use the authenticated VPN DNS settings with a tunnel-bound resolver. |
| `cipher AES-256-GCM` | Remains an advisory directive. The peer negotiates an allowed AEAD cipher with TLS exporter derivation. Fixed AEAD compatibility is unavailable in this import mode. |

Use `ovpn-inspect -capabilities -protonvpn-server-name "$VPN_SERVER_NAME"`
to see classifications for this import mode. The default inspector and
parser retain their strict policy for these options.
[Live results](EXTERNAL_INTEROP.md#proton-vpn) · [Proton manual OpenVPN setup](https://protonvpn.com/support/linux-openvpn)
