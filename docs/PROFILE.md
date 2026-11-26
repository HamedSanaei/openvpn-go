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
| `port`, `rport` | Numeric remote port from 1 to 65535. |
| `remote-random` | Shuffle the complete list once at `client.New`. `profile.Parse` returns declared order. |
| `ca` | Relative PEM certificate bundle path or `<ca>` block. Required. |
| `cert` | Relative PEM client certificate chain path or `<cert>` block. Required with `key`, except when password-only authentication is explicitly authorized. |
| `key` | Relative PEM client private key path or `<key>` block. The unencrypted key must match the certificate. |
| `auth-user-pass` | Relative path, `<auth-user-pass>` block, or bare directive with `profile.Options.Credentials`. Material contains exactly the username and password on separate lines. Their surrounding spaces are preserved. |
| `tls-auth` | Relative Static Key V1 path with optional direction `0` or `1`, or `<tls-auth>` block. |
| `tls-crypt` | Relative Static Key V1 path or `<tls-crypt>` block. |
| `tls-crypt-v2` | Relative wrapped client PEM key path or `<tls-crypt-v2>` block. |
| `key-direction` | `0` or `1` for `tls-auth`. Omission allows bidirectional mode. Both forms must agree when supplied together. |
| `auth` | `SHA1`, `SHA256`, `SHA384` or `SHA512`, case-insensitive. Selects the OpenVPN auth digest, including the HMAC for `tls-auth`. The default is `SHA1`. |
| `data-ciphers` | Ordered, colon-separated subset of `AES-256-GCM`, `AES-128-GCM` and `CHACHA20-POLY1305`, with each cipher listed at most once. Omission offers all three. |
| `cipher` | A single supported AEAD produces an `ignored_directive` warning. Configure the negotiated offer with `data-ciphers`. |
| `remote-cert-tls` | `server`. Requires explicit leaf Key Usage and TLS server Extended Key Usage. |
| `verify-x509-name` | `value [subject\|name\|name-prefix]`, with `subject` as the default. See identity policy below. |
| `tls-version-min` | `1.2` or `1.3`, optionally followed by `or-highest` on a recognized version. Defaults to TLS 1.2. |
| `tls-version-max` | `1.2` or `1.3`. Defaults to TLS 1.3. |
| `allow-compression` | `no`. |
| `nobind` | Requests the default ephemeral local socket. |
| `disable-dco` | Requests the standard userspace data path. |
| `persist-key`, `persist-tun` | Accepted with an `ignored_directive` warning. The library owns session keys and the caller manages the tunnel. |
| `resolv-retry` | `infinite` or nonnegative seconds up to 2,147,483,647. Reports `ignored_directive`. |
| `verb` | Levels 0 through 11. Reports `ignored_directive`. |

Every other directive is a fatal error. This includes server mode, static-key
mode, compression and compression framing, cipher fallback, executable
hooks, includes, external verification mechanisms and options that alter
the security policy. Known directive names, such as `compress` and
`data-ciphers-fallback`, appear in the diagnostic. An unknown token is
represented by its line and the `unsupported_directive` code.

## Remote precedence

With top-level `remote` entries, final `proto`, `port` and `rport` values
set defaults. Explicit `remote` arguments override them. With connection
blocks, each block inherits the defaults at its opening, including control
protection. Inside the block, process `remote`, `proto`, `port` and `rport`
in order. Later settings override earlier settings for the same field.
The supported block directives are `remote`, `proto`, `port`, `rport`,
`nobind`, `key-direction`, `tls-auth`, `tls-crypt` and `tls-crypt-v2`.
A block's protection replaces its inherited protection. Conflicting modes
within the same scope are errors. Empty or nested connection blocks and
profiles combining block and top-level remotes are errors. Defaults are
UDP and port 1194. Address-family constraints also apply to IP literals.

`client.New` keeps all candidates, with their verification policies and
control keys attached when `remote-random` reorders them. `Connect`
starts at the first candidate and advances on recoverable failure.
Applications configure the retry budget through `client.Config.Retry`.
[Failover and reconnect](LIFECYCLE.md)

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
