# Production-facing API and lifecycle

## Status

This document describes the intended embedding boundary; it is not a release
or support claim. The [threat model](threat-model.md) records unresolved
release blockers, and the [release checklist](release-checklist.md) defines
the evidence required for a supported release. `sshz` and `sshzd` are demos,
not deployment templates. The examples under
[`examples/production/`](../examples/production/) demonstrate fail-closed
integration patterns.

## Compatibility policy

sshz is currently pre-1.0 and has no stable release line. Until a release
explicitly declares API version 1, every Zig API may change between minor
releases. Releases must call out changes to the production-facing surface below
and provide a migration note for source-breaking changes.

The candidate production-facing surface is the `sshz` module's
`SshzClient`, `SshzServer`, event and event-payload types,
`ResourceLimits`, deadline/key-lifetime types, `SshOpenFailureReason`,
`KeepaliveToken`, `KeepaliveStatus`, `KeepaliveTransmission`,
`KeepaliveOutcome`, `KeepaliveReply`, `SshzError`, and buffer helper types.
After API version 1, these names,
their documented semantics, and default resource limits follow semantic
versioning: source-breaking changes require a major version; additive events
or errors require at least a minor version; fixes that preserve the contract
may be patches. Zig compiler-version changes are compatibility changes and
must be stated in release notes.

Everything reached through `.session`, public implementation fields, the
`client_session.zig`, `server_session.zig`, `channel.zig`, and `protocol.zig`
modules, packet inspection/exercise helpers, and `requestRead`,
`requestWrite`, `requestEvent`, `advance`, and `getRecvBuffer` is
**internal/unstable**, even where Zig currently exposes it. Agent and TCP
forwarding APIs are **experimental** until their authorization contracts have
dedicated tests and documentation. Demo program APIs and behavior carry no
compatibility guarantee.

Applications should pin an exact sshz revision and Zig version, compile with
the next candidate before upgrading, and never infer compatibility from a
successful protocol handshake.

## Construction, ownership, and cleanup

Create one `SshzClient` or `SshzServer` per ordered, reliable byte stream.
Supply a cryptographically secure `std.Random`, an allocator whose lifetime
contains the session, and explicit validated `ResourceLimits` through
`initWithLimits`. The client's second argument is the username; the server's
is one OpenSSH private host-key file. Initialization copies/decodes the values
it must retain.

The object is single-owner and not thread-safe. Serialize all calls. On every
exit path:

1. stop dispatching new application work;
2. close the transport so no more peer input arrives;
3. cancel or reap subprocesses and close forwarded resources owned by the
   application;
4. call `deinit()` exactly once.

`deinit` clears session packet buffers and key material. It does not close the
application's socket or erase copies held by the application, allocator,
credential store, logs, crash dumps, or kernel. Treat an unexpected library
error as terminal: close and deinitialize rather than attempting to resume.
Fatal protocol/resource/key-lifetime paths latch fail-closed state and later
I/O returns `SessionTerminated`.

## The transport pump

sshz performs no transport I/O. Repeatedly call `getNextEvent()` and service
exactly the returned requirement:

| Result | Caller action |
| --- | --- |
| `ReadyToConsume(n)` | Read at most `n` ordered bytes from the peer and pass each non-empty chunk to `write()`. Zero bytes means transport EOF, not progress. |
| `ReadyToProduce(n)` | Call `peek(n)`, write some or all of the returned slice to the peer, then call `consumed(actual_written)`. |
| `ReadyToConsumeAndProduce` | Service either ready direction without assuming an order. A full-duplex poller should keep both interests armed. |
| `Event(code)` | Complete the policy/application action synchronously, then call `clearEvent(code)`, except for events with explicit decision methods. |
| `error.NotReady` | Wait for transport readiness, a deadline tick, or application work; do not spin. |

`write()` copies input before returning and accepts partial fulfillment of the
announced amount. For both roles, the advertised consume count is the remaining
bytes in the current incremental read (identification, packet header, or packet
body including its MAC), not spare packet-buffer capacity. After a partial
`write()`, query readiness again or subtract the accepted count; after completing
a requirement, query again before consuming more stream bytes. A coalesced
following packet must remain in the transport or caller-owned input buffer until
requested. Never pass more than the current requirement.
`peek()` returns borrowed session storage. Keep it only through the transport
write and call `consumed()` with the exact count actually written, including
partial writes; never mutate or retain the slice. Do not call `consumed()` for
bytes the transport did not accept.

An event remains pending until cleared or decided. Repeated
`getNextEvent()` calls may return it again. Do not clear an event before its
payload is processed. All slices in events (`username`, key blobs, passwords,
commands, data, descriptions, and similar fields) are borrowed from session
storage and become invalid when the event is cleared/accepted/rejected, on
another state-mutating call that releases it, or at `deinit`. In particular,
copy an `RxData` or `RxExtendedData` payload before clearing its event if the
application cannot consume it synchronously. Copy all other data that must
outlive the callback, and protect/erase copied secrets.

The buffer from `getChannelWriteBuffer(channel)` is also borrowed. Copy no more
than its length, immediately call `channelWriteComplete(channel, count)`, and
do not use the slice afterward. An empty buffer means the channel cannot
currently accept data. Inputs to channel-open/rejection APIs should
conservatively remain alive until the corresponding open/failure output has
been pumped because some current implementation paths retain slices.

### Discarding queued client data

`SshzClient.discardUnframedChannelWrite(channel_id)` returns the number of
accepted plaintext payload bytes removed from that channel's write queue.
It is an explicit, client-only operation; it installs no automatic policy.
It works during rekey and with zero peer-window credit without closing the
channel. The server role returns `UnimplementedService`.

Only data accepted through `channelWriteComplete` and not yet framed is
discarded. The discarded suffix is erased, immediately releasing its share
of the configured pending-data budget. A framed prefix remains reserved until
the caller finishes consuming that packet. It cannot be retracted even if
none of the packet has reached the transport. The current packet, cipher and
compression sequencing, peer-window charge, and unrelated channels remain
intact. No peer credit is refunded, and bytes already handed to an
application-owned transport queue are outside this API's ownership.

Call this only after finishing any `getChannelWriteBuffer`/
`channelWriteComplete` pair. Do not retain or resubmit a previously borrowed
write slice across the discard. Bytes merely copied into a borrow but not
accepted by `channelWriteComplete` are neither counted nor cancelled. Acquire
a fresh buffer for later data; it remains empty while the framed prefix is
in flight. Repeated discard on an open channel returns zero until more
unframed data has been accepted.

The API accepts active client channels, including forwarding channels.
Unknown, not-yet-open, close-sent/received, and closed channels return
`UnexpectedResponse` without changing the queue. Terminated sessions return
`SessionTerminated`. A locally queued EOF or CLOSE is preserved, not created
or cancelled. Removing its last unframed predecessor may make that control
packet writable immediately, subject to existing rekey, pending-read, and
write-side ordering. Continue pumping any framed packet normally; do not
discard its bytes from the transport.

The production client example tests this operation through its real pump
with partial encrypted writes, exhausted peer credit, and a complete rekey.
The peer receives only the preserved prefix and subsequently accepted data.

## Client event loop and host identity

`CheckHostKey` is a mandatory trust decision emitted after the key-exchange
signature proves possession of the presented key, but before user
authentication. Bind the decision to the intended canonical endpoint and a
trusted key database:

1. inspect/copy `raw_key` and/or `fingerprint`;
2. compare against pinned or strictly managed trust state;
3. call exactly one of `acceptHostKey()` or `rejectHostKey()`.

`clearEvent(CheckHostKey)` fails with `badClearEvent`; unknown, changed,
missing, or policy-error keys must be rejected. Trust-on-first-use is an
explicit application policy requiring atomic persistence and changed-key
rejection, never a default. Rekey is bound to the initially accepted key and a
change returns `HostKeyChanged`. See [the host-key API](host-key-api.md).

Credential request events borrow or copy credentials only for the required
setter call. Do not log them. Clear ordinary informational/request events only
after setting the requested value. `EndSession` is terminal. The current
client automatically opens a session channel after authentication (shell by
default, or `setAutoExecCommand`). The automatic shell requests a PTY with
default terminal settings unless `setAutoPty` supplies them. Automatic exec is
non-PTY by default, preserving separate `RxData` and `RxExtendedData` streams;
call `setAutoPty` before or after `setAutoExecCommand` to explicitly request
PTY+exec. A PTY may merge stderr into terminal output and apply terminal output
processing. This automatic-session behavior is pre-1.0 and unsuitable as an
implicit production policy. Configure the intended operation before driving
the handshake.

Call `setAutoSessionEnabled(false)` before authentication for a tunnel-only
client. Authentication then emits `Connected` without opening a session
channel. Closing its final ordinary channel leaves the authenticated transport
active, including while it has zero channels, so the application may later
open another `direct-tcpip` channel. A server disconnect, transport EOF,
explicit application shutdown, authentication failure, timeout, or fatal
library error still ends the transport. Automatic shell/exec clients retain
their existing session-wide `EndSession` behavior after the final ordinary
channel closes.

For an automatic shell or exec, save or query `automaticSessionChannelId()`.
`channelExitResult(id)` returns the first valid RFC 4254 terminal result:
`.Status`, `.Signal` (including core-dump, error-message, and language-tag
fields), or `.NoResult` after a close without either request. Results survive
channel removal and `EndSession`. Signal strings are allocator-owned by the
client and borrowed until `clearChannelExitResult(id)` or `deinit`; copy them
before that point if they must live longer.

Completed results are never silently evicted. Each session channel reserves
one fixed-capacity result slot before its open is sent. Once retained completed
results consume the configured channel capacity, another session open returns
`tooManyChannels` until the application calls
`clearChannelExitResult(id)`. Clearing an open channel's reservation returns
false, so close cannot lose its result. Open failures release their reservation
automatically. The production client example treats status zero as success and
reports nonzero, signal, and missing-result outcomes as terminal errors.

## Explicit acknowledged client keepalives

`requestKeepalive()` queues `keepalive@openssh.com` with `want_reply=true`
after authentication and returns a value-owned `KeepaliveToken`. It never
writes channel data or installs automatic probes, a clock, deadlines, retries,
or a connection-health policy. It is valid on an authenticated zero-channel
client and can queue while output or rekey is in progress.

Poll `keepaliveStatus(token)` for a value-owned snapshot. No new event-loop
variant is required. The snapshot's `token`, `transmission`,
`transport_flushed`, and `outcome` contain no borrowed storage:

| Field/state | Meaning |
| --- | --- |
| `transmission.Queued` | The request is accepted but not yet framed; output or rekey may be blocking it. |
| `transmission.Emitting` | The request is framed, but some or all bytes remain unconsumed. A zero-byte write is not progress. |
| `transmission.HandedToTransport` | The caller has called `consumed` for every byte of this packet, including its padding and MAC. This is not itself proof of a TCP send or a peer reply. |
| `transport_flushed` | The caller has explicitly confirmed its underlying transport accepted all bytes through this request with `markKeepaliveFlushed(token)`. |
| `outcome.Pending` | No acknowledgement or terminal observation yet. |
| `outcome.Acknowledged(.Success or .Failure)` | A correlated SSH `REQUEST_SUCCESS` or `REQUEST_FAILURE` arrived. Both prove peer responsiveness; failure usually means the peer does not implement this request. Neither proves remote application progress. |
| `outcome.Cancelled` | The caller abandoned observation with `cancelKeepalive(token)`. |
| `outcome.Disconnected` | `EndSession`, fatal fail-closed cleanup, or deinitialization ended a still-pending request. |

### The flush boundary belongs to the transport

For a direct socket pump, call `consumed(actual_sent)` only after each
successful send. Once the snapshot becomes `HandedToTransport`, call
`markKeepaliveFlushed(token)` and start any reply deadline at that time, not
at enqueue. This method returns `NotReady` before handoff and is idempotent
after handoff. It trusts the caller's flush assertion; sshz does no I/O.
This local transport flush does not mean TCP acknowledgement or peer receipt.

A buffering adapter may consume bytes into an application-owned ordered
output queue. When the token first becomes `HandedToTransport`, record the
queue's cumulative byte boundary immediately after that `consumed` call.
`consumed` can prepare subsequent packets, but never consumes those bytes
itself. Preserve the queued bytes and wait until the underlying stream
accepts everything through the recorded boundary before marking the token
flushed. Waiting for the entire queue to drain is also valid, but may delay
the deadline under continuous output. Never interpret handoff to an unsent
queue as a successful send. An acknowledgement can arrive before an adapter
reports the flush; it still belongs to the same token.

The production client example's opt-in keepalive test exercises its real
`pumpOnce` with partial direct-transport writes, explicit flush marking, and
EOF/CLOSE queued behind a cancelled probe without further peer input, all
without sockets or a remote server.

### Ordering, cancellation, and token lifetime

Keepalives and `requestRemoteForward`/`cancelRemoteForward` share exactly one
outstanding reply-requesting global request. A second request returns
`ResourceLimitExceeded`; the caller may wait and retry without terminating
the session for this documented local contention case. Existing forwarding
events and payloads remain unchanged.

Waiting for a keepalive reply does not gate deferred channel output. Queued
EOF/CLOSE and other channel writes resume after the global request's handoff,
subject to rekey gating and processing any already-received packet first.

After an acknowledgement, use `clearKeepalive(token)` to release the retained
result before requesting another keepalive. Clearing a `Pending` result
returns `NotReady`. Tokens are scoped to the issuing client, never wrap or
repeat during that client's lifetime, and must not be used with another
client. Released or stale tokens return `InvalidKeepaliveToken`. Copy any
snapshot needed after destroying the client; copied acknowledgements remain
valid independently of the client.

`cancelKeepalive(token)` is idempotent and does not replace an already terminal
outcome. Cancelling a `Queued` request retracts it. Once `Emitting`, even if
no bytes have been consumed, encryption/compression state has advanced and
the packet cannot safely be removed. Continue pumping the exact stream:
the cancelled request drains normally and reserves its reply slot until the
old reply arrives or the connection ends. Clearing the cancelled result
**does not** release this slot. A late reply is discarded for that cancelled
request, never credited to a newer probe or forwarding request. If no reply
ever arrives, close/deinitialize to abandon the slot; there is no unsafe
timeout-reset operation.

For a grace period that can recover on a late reply, keep the same request
`Pending` rather than cancelling it. The application owns all timeouts,
including a separate queued/send-stall budget. A local observation timeout
alone does not release the slot or alter sshz's state. Unsolicited responses
and responses to an unframed request are protocol errors. SSH global replies
have no wire IDs: correlation follows the protocol's ordered, one-reply-per-
request contract, not a peer-echoed token. An extra response after completion
cannot be distinguished from a later request's response if a nonconforming
peer sends it only after the later request; local tokens do not add wire
identities.

## Server authentication and authorization

`UserAuth` means protocol-level parsing succeeded; it does **not** mean the
account is authorized. A public-key event may represent either an unsigned
probe or a request whose signature has already been verified. The application
applies the same username/key policy to both. Allowing a probe emits `PK_OK`
but does not authenticate; only allowing the later valid signed request can
emit authentication success.

While the borrowed `UserCredentials` is pending, evaluate username, method,
key, credential verifier, account state, source policy, and rate limits. Then
call `decideUserAuth(.Allow|.Deny)` exactly once; it resolves and clears the
event atomically. `grantAccess(bool)` followed by `clearEvent(event)` remains a
compatibility path, and clearing an undecided `UserAuth` event denies by
default. Server keyboard-interactive is not advertised or accepted until its
RFC 4256 challenge-response exchange is implemented. Deny `none`, password,
unknown users, backend failures, and unsupported key policies by default.
Never use password equality, “any valid key,” or a missing policy as acceptance.

Authentication callbacks must be bounded and side-channel reviewed.
Application-wide attempt/source limits complement the per-session
`max_server_auth_attempts`. A backend timeout or exception is denial followed
by connection cleanup, not acceptance or an indefinite pending event.

## Channel lifecycle

1. A peer open produces `ChannelOpenRequest`. Authorize the channel type and
   every destination/origin field, then call `acceptChannelOpen(id)` or
   `rejectChannelOpen(id, reason, description)`. Never merely clear this event.
   This includes `Session` opens; the server never confirms them implicitly.
2. An outbound open is not usable until `ChannelOpened`; handle
   `ChannelOpenFailure` as final for that channel. `Connected` reports an
   accepted server channel or the client's automatic session channel.
3. For server `ChannelRequest`, authorize `Shell`, `Exec`, `Subsystem`, `Env`,
   and `AgentForward` separately. **Current limitation:** clearing a
   reply-requesting event sends success; there is no request-failure method.
   To deny, queue `sendChannelClose(channel)` before clearing. Treat this as a
   release blocker for applications needing request-level rejection.
   Session-specific requests are rejected at the protocol boundary when their
   recipient is not a `Session` channel and never reach application callbacks.
4. Process `RxData`/`RxExtendedData` synchronously and clear the event to
   release the borrowed payload. Automatic receive-window replenishment remains
   the default. An application that needs bounded downstream backpressure may
   call `setAutoChannelReadCreditEnabled(false)` before any channel opens.
   Clearing a borrowed data event then releases sshz's packet storage without
   crediting the peer. After consuming or durably buffering bytes, call
   `channelReadConsumed(channel_id, count)` with a positive count no greater
   than that channel's delivered-but-uncredited bytes. Partial credit is
   allowed. Unknown, automatic-credit, closing, and closed channels reject the
   call; zero, over-credit, and arithmetic overflow are errors. Window adjusts
   remain channel-specific and are scheduled round-robin with pending channel
   output. Agent channels retain automatic credit.
5. A client ordinary channel emits `ChannelEof(channel_id)` exactly once after
   all earlier data events on that channel have been observed. If EOF and close
   are both received, `ChannelEof` is observed before
   `ChannelClosed(channel_id)`. One channel's EOF or close does not end its
   peers.
6. `sendChannelEof` ends the local data direction after queued data.
   `channelEofFlushed` reports when that data and EOF have been written to the
   transport. `sendChannelClose` abandons unsent data and starts close exchange.
   `ChannelClosed` is emitted when the ordinary channel close handshake
   completes. The channel slot remains reserved until that event is cleared;
   clearing it permits slot reuse. Agent channels continue to use
   `AgentChannelClosed`.
7. After close/end-session, inspect `channelExitResult` for session channels,
   then call `clearChannelExitResult` and release every application resource
   bound to that channel.

Reject forwarding and agent requests unless separately authorized. Validate
resolved destinations too, preventing DNS rebinding and access to loopback,
link-local, metadata, privileged, or internal services contrary to policy.

In manual-credit mode, configure `initial_channel_window` no larger than the
application's bounded per-channel receive storage. sshz does not add a socket
queue or retain application payload after the borrowed receive event is
cleared.

## Limits, deadlines, and rekey

Defaults are compatibility bounds, not a deployment policy. Configure
per-session packet, channel, buffering, pre-authentication, authentication,
KEX, decompression, and global-request limits; add process-wide connection,
memory, CPU, file-descriptor, bandwidth, and source limits. See
[resource limits](resource-limits.md).

sshz does not read a clock. Call `initializeDeadlines(now)` once, use one
monotonic tick unit, call `noteActivity(now)` only for real progress, and call
`tick(now)` often enough to enforce handshake, authentication, idle, total,
and key-age limits. A timeout is terminal. The embedding transport also needs
bounded connect/read/write operations so a blocked callback cannot prevent
ticks.

Byte/packet thresholds schedule automatic rekey; configure a key-age threshold
and continue pumping while rekey is in progress. Application initiation may
return `NotReady` while output is gated. `keyLifetimeStatus()` is diagnostic,
not permission to exceed limits. Never disable or weaken rekey limits to work
around backpressure.

## Error taxonomy

- `ResourceLimitConfigError` and `DeadlineError` identify caller
  configuration/clock-contract bugs. Fix configuration; do not retry a live
  session after a monotonic-clock violation.
- `NotReady`, `cannotAcceptWrite`, `notProducing`, and `notEnoughData` normally
  indicate pump ordering/backpressure mistakes. `InvalidChannelReadCredit` and
  `ChannelReadCreditExceeded` identify invalid manual receive-credit calls.
  `InvalidKeepaliveToken` identifies a stale/released token; local
  `ResourceLimitExceeded` from a second outstanding global request or retained
  keepalive result is the documented contention case above.
  `UnexpectedResponse` from `discardUnframedChannelWrite` identifies an invalid
  channel lifecycle for that local operation, not newly received peer input.
  Correct the poll/accounting state; never drop or duplicate bytes.
- `BufferError`, malformed framing/MAC, negotiation, unexpected response,
  channel-window/packet, auth/KEX/resource, host-key-change, and
  key-lifetime errors are peer/session failures. Close and deinitialize.
- Allocator, crypto, compression, credential/policy, transport, and
  application errors fail closed. Do not map an operational failure to a
  positive host-key, authentication, channel, or forwarding decision.
- `EndSession` and deadline outcomes are terminal lifecycle results, even when
  the peer closed cleanly.

Do not match only today’s exhaustive error set to decide safety. Future
additive errors must inherit the default terminal behavior until reviewed.
