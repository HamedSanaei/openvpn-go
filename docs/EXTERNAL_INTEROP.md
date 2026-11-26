# External OpenVPN compatibility tests

Run these tests from a disposable lab using a router or account explicitly
authorized for testing. Keep downloaded profiles, credential files,
keys and peer logs in a private directory outside the checkout. Publish
only the probe's redacted JSON and a summary of the exact test case.

## Running the probe

The probe uses the regular profile parser and client. It records registered
directive names, warning and failure codes, validated transport and control
protection, authentication mode, and the negotiated TLS version and AEAD
cipher when a connection succeeds. It keeps profile values, endpoints,
assigned addresses and raw errors out of the report.

~~~sh
export OVPN_EXTERNAL_PROFILE=/path/to/private/client.ovpn
export OVPN_EXTERNAL_ROOT=/path/to/private
export OVPN_EXTERNAL_AUTH_FILE=/path/to/private/auth.txt
go test -v -count=1 -timeout 1m -run '^TestExternalProfile$' ./tests/interop
~~~

`OVPN_EXTERNAL_ROOT` authorizes profile-relative material references.
`OVPN_EXTERNAL_AUTH_FILE` supplies the two-line username and password for
a bare `auth-user-pass` directive. Omit whichever variables the profile
doesn't need. Set `OVPN_EXTERNAL_PASSWORD_ONLY=1` only for a test profile
designed to use verified TLS and password authentication without a client
certificate. The default client policy still requires verified server
identity, TLS 1.2 or later, negotiated AEAD, TLS exporter key derivation
and a peer ID.

The probe selects the first declared remote. Use `OVPN_EXTERNAL_REMOTE`
to select another using its one-based profile index. Repeat per transport
and profile. The default expected outcome is `connected`, which verifies
negotiation. To verify data and reconnect, set `OVPN_EXTERNAL_ECHO` to an
IPv4 ICMP echo endpoint owned by the test lab and set
`OVPN_EXTERNAL_EXPECT=verified`. The probe sends only a synthetic nonce
through the packet API, closes the first peer transport and checks another
round trip through the new session. It installs no host routes or DNS
settings. To reproduce a known rejection, set the expected outcome to its
reported `stage:code`, for example `parse:unsupported_directive`.
An unexpected outcome makes the test fail.

## MikroTik RouterOS

The virtual reference is **CHR 7.25.2 stable, x86_64** on QEMU, with a
single isolated Ethernet interface. The official ZIP
`chr-7.25.2.img.zip` had SHA-256
`b0df0acb3f2070fb94d9e30bd8a8566bb622034786bb4f759f837cf2aa05bacb`.
The physical target is **RB5009UG+S+IN, arm64, RouterOS 7.25.2**.
That target is pending a run on authorized hardware.
[MikroTik stable releases](https://download.mikrotik.com/routeros/latest-stable.rss) ·
[Pinned CHR archive](https://download.mikrotik.com/routeros/7.25.2/chr-7.25.2.img.zip) ·
[RB5009 board](https://mikrotik.com/product/rb5009ug_s_in)

On the disposable router, provision a lab CA, a server certificate and
private key with a dedicated test identity, a client certificate from the
same CA, and a disposable PPP account called `ovpnlab`. The lab values
below assume the imported server certificate is called `labserver`. Repeat
the listener command with the other transport, port and cipher combinations.

~~~text
/ppp/profile/add name=ovpnlab local-address=10.61.0.1 remote-address=10.61.0.2
/interface/ovpn-server/server/add name=tcp256 port=1194 protocol=tcp mode=ip default-profile=ovpnlab certificate=labserver tls-version=only-1.2 cipher=aes256-gcm auth=null require-client-certificate=yes disabled=no
~~~

Assign the PPP account that profile. The Go probe uses a project-authored
profile with `dev tun`, a lab remote, certificate and password
authentication, `remote-cert-tls server`, an exact
`verify-x509-name ... name`, TLS 1.2 and `data-ciphers` restricted to
the selected AES-GCM cipher. Use the PPP local address as the echo target.
The pinned Community reference used the same identity and TLS settings and
explicit fixed AEAD in both `--data-ciphers` and
`--data-ciphers-fallback` to exercise the RouterOS configuration.
[RouterOS OpenVPN](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN) ·
[Server settings](https://manual.mikrotik.com/docs/cli-reference/interface/ovpn-server/server/)

| CHR profile | OpenVPN Community 2.6.23 reference | OpenVPN Go default policy |
|---|---|---|
| TCP 1194, AES-256-GCM | Verified TLS 1.2 identity and ICMP echo | Control negotiation timed out |
| UDP 1195, AES-256-GCM | Verified TLS 1.2 identity and ICMP echo | Control negotiation timed out |
| TCP 1196, AES-128-GCM | Verified TLS 1.2 identity and ICMP echo | Control negotiation timed out |
| UDP 1197, AES-128-GCM | Verified TLS 1.2 identity and ICMP echo | Control negotiation timed out |

The reference received an authenticated peer ID and IPv4 assignment. Its
push omitted the cipher selection and TLS exporter signal. The reference
used the configured fixed cipher. OpenVPN Go published no negotiated
session in these cases. The reference push establishes a difference from
the client's required negotiation. The client timeout alone does not
identify which control exchange stalled. Data and reconnect support for
the Go client, RouterOS 6, and the physical target remain unverified.

A repeat with the finalized race-enabled probe reproduced
`connect:operation_timed_out` for both UDP cases, while both TCP cases
returned `connect:network_failure`. No session was activated. These are
observed negative outcomes, not a diagnosis of the wire-level cause or
successful interoperability certification. Keep the existing fail-closed
policy until the missing negotiation and transport behavior are understood.

The probe itself passed a separate positive control against OpenVPN
Community 2.6.23: authenticated TLS 1.2/AES-256-GCM, synthetic IP traffic
and a second round trip after reconnect. Regression tests also cover
redaction, rejection of a legacy CBC profile before dialing and bounded
credential-file parsing.

## Provider and Access Server profiles

Run the probe against one unchanged export per authorized test case.
Record the export type, transport, authentication mode, control protection,
exact available server version and the stage/code. A server version can be
marked undisclosed when the provider does not expose it. List any tested
profile edits as separate cases.

A self-hosted Access Server lab used **3.2.4** (`3.2.4-f3c295a7-Ubuntu26`),
with the official Linux amd64 container pinned to
`docker.io/openvpn/openvpn-as@sha256:6b8252ead84638fb5d6bf1d617b07299d170c5102245675e3c1720bbeb9ac6e2`.
Two exports were generated using a disposable local account and kept outside
this repository. Both advertise TLS 1.3 and carry inline CA, certificate,
key and `tls-crypt-v2` material. The original exports request
`cipher AES-256-CBC`, which is outside this project's AEAD-only policy.

| Access Server export | Go probe outcome | Traffic / reconnect |
|---|---|---|
| Auto-login | `parse:unsupported_directive` (`cipher`, policy-disabled) | Not attempted |
| User-locked (`auth-user-pass`) | `parse:unsupported_directive` (`cipher`, policy-disabled) | Not attempted |

The external Community reference attempts also failed to reach the lab
listener (connection refused); no successful Access Server negotiation
or transport interoperability is established by this run. The reported
parser rejection is reproducible without network access. Reconfigure an
AEAD-only lab and repeat with a new, separately identified export before
claiming compatibility. No security policy was relaxed to accept these
profiles. [Access Server image](https://hub.docker.com/r/openvpn/openvpn-as)

| Provider | Export to test | Status |
|---|---|---|
| Proton VPN | Current manual OpenVPN profile and separate OpenVPN credentials | Pending authorized account and export |
| Windscribe | Authorized manual OpenVPN configuration from the Config Generator | Pending authorized account and export |
| ExpressVPN | OpenVPN configuration and credentials from Manual Configuration | Pending authorized account and export |

[Proton VPN manual setup](https://protonvpn.com/support/vpn-login) ·
[Windscribe Config Generator](https://windscribe.com/getconfig/openvpn) ·
[ExpressVPN manual setup](https://www.expressvpn.com/support/vpn-setup/manual-config-for-windows-with-openvpn/)
