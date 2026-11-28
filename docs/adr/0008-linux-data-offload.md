# ADR 0008 · Linux data channel offload

The pure-Go userspace data path remains the shipped backend.

Linux 6.16 introduced the mainline `ovpn` driver. Distribution backports
and the earlier OpenVPN 2.6 `ovpn-dco` module have distinct compatibility
requirements. Test availability by probing the actual generic netlink
family and required operations in the target namespace. An OS version
alone cannot establish compatibility. OpenVPN 2.7 and OpenVPN 3 Core are
behavioral references for the mainline interface. [Linux ovpn netlink ABI](https://docs.kernel.org/netlink/specs/ovpn.html) · [OpenVPN DCO compatibility](https://github.com/OpenVPN/openvpn/blob/v2.7.9/README.dco.md)

An optional backend would hand the kernel a transport socket, peer
address, data cipher, and per-direction key and nonce material after
verified TLS and negotiation. The host service would require scoped
network administration privilege. Limit that service to one owned
network namespace and use a tested peer and key installation state
machine. Keep TLS, authentication, rekey initiation and policy in
userspace. Roll back partial key or peer installation and verify
retiring-key deletion before reporting cleanup. Gate backend choice by
transport, selected data channel format, AEAD, and kernel support.
Do not fall back in a live session after installing data keys. Any
preauthorized fallback must clean up the backend and start a fresh
verified session.

The recorded three-client sample exercises userspace at a local packet
budget and provides no measurements on a DCO-enabled target. It does
not justify the additional privilege, key custody and replay boundary
today. Before implementing the optional backend, measure a sustained
workload on applicable hardware, including CPU and throughput,
reconnect behavior and rollback. Add isolated coverage for rekey,
packet replay, peer deletion, application crash, and unsupported
kernel responses. Keep DCO results and user-space results distinct.
[Reproducible comparison](../RESOURCE_EVIDENCE.md)

## Lab availability for issue #118

On Linux amd64 WSL2 `6.18.33.2-microsoft-standard-WSL2`, `genl ctrl list`
exposed no `ovpn` or legacy DCO family and `/proc/modules` showed no loaded
DCO driver. The available Ethernet interface was virtual. This leaves
the native 1/10 GbE comparison pending. The userspace backend remains
the production path while the performance and privilege tradeoffs await
measurement. [Native load protocol](../NATIVE_LOAD.md)

The authorized KVM lab, Linux `7.0.0-44-generic`, exposed the mainline
`ovpn` family. Link creation and removal worked inside the disposable
namespace. Packaged OpenVPN 2.7.0 (`2.7.0-1ubuntu1.4`, executable SHA-256
`06d101129eec1816fe2f79910c292a33da2779e06e073dbc4de295ad6dc93ff6`)
exchanged IPv4 traffic with verified TLS and AES-256-GCM between two
isolated namespaces in userspace and with `ovpn` links on both ends.
This confirms driver availability and basic interoperability. Native
NIC throughput, CPU attribution, rekey and crash cleanup measurements
remain required before selecting a shipped DCO backend.

## Decision after the sustained virtual-network comparison

Retain the pure-Go userspace backend. The new two-vCPU lab comparison
found a substantial benefit for mainline DCO between Community peers
over a virtual link. It establishes a reason to run a physical-network
evaluation. A veth throughput measurement cannot qualify a physical
NIC or the project's client data plane. Backend selection still
depends on physical-network evidence, scoped key lifecycle and
privilege handling, and independent security review.
[Sustained comparison and reproduction](../evidence/dco-veth-2026-11-28.md)
