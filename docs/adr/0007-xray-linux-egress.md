# ADR 0007 — Xray egress through a host-owned TUN

The integration target is the 3x-ui checkout at
`e50f949a04174e26de247b40baa2e260415174e9`. Its release workflow selects
Xray-core 26.10.21 (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`).
3x-ui supplies Xray outbound configuration. Xray's built-in `freedom`
outbound takes a Linux socket interface and returns bind errors to its
dialer. This is the integration boundary.
[3x-ui release configuration](https://github.com/MHSanaei/3x-ui/blob/61b129d5b396dfeb56f738f5b9320a6f23bf8163/.github/workflows/release.yml) · [Pinned Xray socket options](https://github.com/XTLS/Xray-core/blob/v26.10.21/transport/internet/sockopt_linux.go) · [Pinned dialer](https://github.com/XTLS/Xray-core/blob/v26.10.21/transport/internet/system_dialer.go)

The host provisions a persistent TUN and routes for sockets bound to it.
`ovpn-xray` attaches to that device, loads a profile and runs the public
OpenVPN client. The integration adapter validates negotiated addresses
against the host's expected configuration at initial connection and
across recovery. The tunnel stays open across recoverable link failures.
Xray routes each outbound flow through its existing OS socket path.

Core packages retain their packet API and TLS policy. The executable owns
the TUN handle it opens. The adapter borrows the packet device and owns
the OpenVPN client. The stock Xray process retains its existing lifecycle
and does not load adapter code. A topology or tunnel address change requires
coordinated host configuration and a new adapter run.
