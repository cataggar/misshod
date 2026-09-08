# sshz

sshz is a minimal, transport-agnostic SSH client and server library written in
Zig. Applications drive its asynchronous state machines over any reliable,
ordered byte stream.

## Features

- Client and server APIs with no internal transport I/O
- Client keyboard-interactive plus client/server public-key, password, and none authentication
- Multiple channels, sessions, port forwarding, and agent forwarding
- Rekeying, delayed compression, resource limits, and deadline enforcement
- Explicit acknowledged keepalives with owned request tokens and transport-flush accounting
- Client-side cancellation of queued, unframed channel data without closing the channel
- Interoperability coverage with OpenSSH, Dropbear, and libssh

The authoritative algorithm list and negotiation rules are in the
[SSH algorithm policy](doc/algorithm-policy.md).

## Quick start

sshz requires [Zig 0.16.0](https://ziglang.org/download/).

```sh
zig build test
zig build production-examples
```

See [getting started](doc/getting-started.md) for library commands and the
`sshz` and `sshzd` demo programs.

For either role, consume-readiness counts cover only the current incremental
read. Leave coalesced following packets in the transport or your own input
buffer until requested; see the [transport pump contract](doc/api-production.md#the-transport-pump).

## Documentation

- [Production-facing API and lifecycle](doc/api-production.md)
- [Getting started and demo programs](doc/getting-started.md)
- [Interoperability testing](doc/interoperability.md)
- [Malformed-input testing](doc/malformed-inputs.md)
- [Stress and soak testing](doc/stress-and-soak.md)
- [Resource limits](doc/resource-limits.md)
- [Threat model](doc/threat-model.md)
- [Release checklist and platform matrix](doc/release-checklist.md)

## Project status

> **Security and support warning:** No independent external security review has
> occurred. sshz is pre-1.0 and unsupported for production use while the
> documented release blockers and evidence gaps remain.

The 2026-08-21 [maintainer-led security review](doc/maintainer-security-review-2026-08-21.md)
found and remediated security defects, but it is not an independent review or
production approval. The
[release checklist](doc/release-checklist.md) defines the evidence and review
required for a supported release. `sshz` and `sshzd` are interoperability demos,
not deployment templates. See [SECURITY.md](SECURITY.md) for private
vulnerability reporting.
