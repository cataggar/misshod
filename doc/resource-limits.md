# Per-session resource limits

sshz exposes `ResourceLimits`, `ResourceCapacities`, `DeadlineLimits`, and
`TimeoutOutcome` from `src/sshz.zig`. `SshzClient.init` and
`SshzServer.init` retain their existing signatures and use the defaults.
Callers that need an explicit policy use `initWithLimits`. Initialization
validates every runtime value against the fixed storage capacities and returns
a typed `ResourceLimitConfigError`; invalid values are never clamped.

These are library **per-session** limits. They are not process-wide admission
control.

## Default build

| Limit | Default |
| --- | ---: |
| SSH wire packet, including an encrypted packet's MAC | 35,000 bytes |
| packet payload | 34,708 bytes |
| channels | 4 |
| advertised initial receive window | 34,653 bytes |
| accepted peer window | `u32` maximum |
| advertised/accepted channel packet data | 34,653 bytes |
| buffered data per channel | 34,653 bytes |
| buffered data across pending channel writes | 138,612 bytes |
| pre-identification lines / identification-phase bytes | 50 / 13,005 |
| pre-authentication packets / weighted work units | 256 / 1,024 |
| server authentication requests | 8 |
| key exchanges, including the initial exchange | 8 |
| packets required between peer rekeys | 0 |
| automatic rekey after encrypted bytes, per direction/key epoch | 1 GiB |
| automatic rekey after encrypted packets, per direction/key epoch | 1,073,741,824 |
| automatic rekey after key age | disabled until configured in caller clock ticks |
| outstanding global requests | 1 |
| decompressed packet payload | 34,708 bytes |
| handshake, authentication, idle, total deadlines | disabled |

## Compile-time channel capacity

The fixed channel table defaults to four entries. An embedding build can opt
into a larger bounded table through the package dependency options:

```zig
const sshz_dep = b.dependency("sshz", .{
    .target = target,
    .optimize = optimize,
    .channel_capacity = 8,
});
```

`ResourceCapacities.channels` reports the selected ceiling.
`ResourceLimits.max_channels` defaults to that ceiling and can enforce a lower
per-session limit, but initialization rejects a value above it. The capacity
must be between 1 and 255.

Increasing the capacity increases every client and server session's fixed
storage even when fewer channels are active. Each channel slot includes a
34,653-byte write buffer, aggregate pending-write capacity is
`channel_capacity * 34,653`, and client exit-result and pending-reply tables
also scale with the capacity. Embedders should account for this linear growth
when deciding whether to place session values on the stack or heap.

The default client authentication strategy remains separately bounded as
before. The server count includes unsupported, probe, and failed requests so a
peer cannot avoid the bound by changing methods.

`ResourceCapacities` publishes the compile-time ceilings. Relationships are
also checked: packet/payload framing must fit, the initial window cannot exceed
the maximum window, channel packets must fit the receive window and
decompression limit, and aggregate buffering cannot be smaller than one
channel's buffer. `ResourceLimits.key_lifetime` names its units explicitly:
`rekey_after_encrypted_bytes`, `rekey_after_encrypted_packets`, and
`rekey_after_monotonic_ticks`. Zero values, byte/packet values weaker than the
documented defaults, values that leave insufficient room to finish KEX before
the AES-CTR/sequence hard bounds, and a zero tick duration are rejected.

## Suggested profiles

- **Compatibility:** use `ResourceLimits{}` and drive external connection
  deadlines. Byte and packet rekeying is enabled by default; key-age rekeying
  needs a caller-clock duration.
- **Interactive service:** retain the packet sizes, reduce channels and the
  maximum peer window if appropriate, keep server authentication attempts
  small, require packets between peer rekeys, and configure all four
  deadlines.
- **Constrained service:** reduce channel count, channel packet/window sizes,
  per-channel and aggregate buffering together. Test the chosen sizes against
  every required peer; SSH peers commonly advertise 32 KiB channel packets.

Deadline and key-age values are ticks in the caller's monotonic clock, not
seconds. For a nanosecond clock, for example, a 30-second duration is
`30 * std.time.ns_per_s`. A production profile should not leave deadlines
or `key_lifetime.rekey_after_monotonic_ticks` disabled merely because the
compatibility defaults do.

## Timeout-driving contract

sshz never reads a wall or monotonic clock.

1. Call `initializeDeadlines(now)` exactly once after session initialization.
2. Call `noteActivity(now)` after transport or application progress that the
   embedding policy considers activity. Merely polling is not activity.
3. Call `tick(now)` regularly. It checks deadlines and key age. A due key age
   schedules local rekey and normal event driving progresses it. A deadline
   returns its existing typed `TimeoutOutcome`, latches the timeout, clears
   session buffers/secrets that can be cleared immediately, and makes further
   I/O fail with `SessionTerminated`; timeout precedence and meanings are not
   changed by key-age checks.
4. `checkDeadlines(now)` performs the same calculation without terminating,
   for callers that need to inspect first. A duration expires when
   `now - start >= duration`.
5. Every supplied value must be at least the last observed value.
   `NonMonotonicTime`, `DeadlinesNotInitialized`, and
   `DeadlinesAlreadyInitialized` make clock-contract mistakes explicit.

Handshake and authentication timers follow the phase observed by `tick` or
`checkDeadlines`; the total timer starts at initialization, and activity moves
only the idle timer. The caller must continue to call `deinit` after every
success or failure.

## Enforcement and failure behavior

Oversized framing, decompression output, identification input, pre-auth work,
authentication attempts, excessive/frequent KEX, invalid channel parameters,
channel receive-window violations, channel packet violations, window
arithmetic overflow, and buffered-data excess return typed errors. Fatal
peer/session violations are latched fail-closed by the public I/O driver;
retries return `SessionTerminated`. Channel data is rejected before receive
window counters change. Window adjustment uses checked arithmetic rather than
saturation.

Only one global request can await an application/peer response. A local second
request is rejected; a server receiving another reply-requesting forwarding
request sends failure while preserving the first pending request.

## Automatic rekey and diagnostics

Both roles schedule the existing RFC 4253 KEX state machine as soon as either
direction reaches a configured byte, packet, or caller-clock age threshold.
Thresholds are evaluated at complete packet boundaries; after a packet reaches
a threshold, KEXINIT is the next locally initiated transport packet. A packet
or application event already committed to the nonblocking interface is
finished first, but queued channel/application output is gated and cannot
bypass rekey. Simultaneous peer/local KEXINIT is folded into the same exchange.

`keyLifetimeStatus()` exposes read-only `KeyLifetimeStatus` diagnostics:
per-direction epoch, encrypted bytes and packets in that epoch, the next SSH
sequence number, activation tick/age when the clock is initialized, and
pending/in-progress rekey flags. It exposes no keys, IVs, MAC material, shared
secrets, or plaintext.

Encrypted byte/packet/age counters reset independently only when that
direction activates its new keys at the corresponding `NEWKEYS` boundary.
SSH sequence numbers do not reset during rekey. The AES-CTR byte position and
SSH sequence number use checked hard bounds; inability to complete safely
returns `KeyLifetimeExceeded`, terminates the session, and never wraps.
The initial session identifier and the client's accepted host identity remain
bound across rekey.

## Caller responsibilities

The embedding application still owns:

- total concurrent and per-source connections;
- sockets, file descriptors, accept queues, transport buffering, and bandwidth;
- allocator-wide memory budgets, threads, processes, subprocesses, and command
  sandboxing;
- account/source rate limits and bans;
- choosing and driving a trustworthy monotonic clock;
- choosing the key-age duration in that clock's documented tick unit and
  driving `tick` often enough to enforce it;
- closing the transport and calling `deinit` after terminal outcomes.

No per-session setting can enforce those application-wide budgets.
