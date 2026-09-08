const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const UNSAFE_TRACEDUMP = util.unsafeTracedump;
const ClientSession = @import("client_session.zig").Session;
const ClientSessionState = @import("client_session.zig").SessionState;
const ServerSession = @import("server_session.zig").Session;
const ServerSessionState = @import("server_session.zig").SessionState;
pub const BufferError = @import("buffer.zig").BufferError;
pub const BufferReader = @import("buffer.zig").BufferReader;
pub const BufferWriter = @import("buffer.zig").BufferWriter;

/// Reading and matching OpenSSH's `known_hosts`, so that an embedder deciding
/// `CheckHostKey` does not have to reimplement the format. Does no I/O.
pub const known_hosts = @import("known_hosts.zig");
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Key = @import("key.zig");
const Protocol = @import("protocol.zig");
const Hasher = @import("hasher.zig").Hasher;
const Channel = @import("channel.zig");

pub const SshzError = std.crypto.errors.Error || std.mem.Allocator.Error || BufferError || IoError ||
    ResourceLimitConfigError || Channel.ChannelError || DeadlineError || PrivKeyError || Key.KeyError;

pub const IoError = error{
    cannotAcceptWrite,
    notProducing,
    notEnoughData,
    noEOLFound,
    badClearEvent,
    InvalidPacketSize,
    InvalidMac,
    UnexpectedResponse,
    tooBig,
    UnimplementedService,
    AlgorithmNegotiationFailed,
    HostKeyChanged,
    NotReady,
    tooManyChannels,
    UnsupportedMessage,
    ResourceLimitExceeded,
    TooManyAuthAttempts,
    TooManyPreAuthPackets,
    TooMuchPreAuthWork,
    TooManyKeyExchanges,
    RekeyTooFrequent,
    InvalidChannelParameters,
    KeyLifetimeExceeded,
    SessionTerminated,
    InvalidKeepaliveToken,
};

pub const ResourceLimitConfigError = error{
    PacketLimitExceedsCapacity,
    PayloadLimitExceedsCapacity,
    InvalidPacketPayloadLimits,
    ChannelLimitExceedsCapacity,
    InvalidChannelWindowLimits,
    InvalidPeerPacketLimit,
    BufferedDataLimitExceedsCapacity,
    InvalidPendingDataLimit,
    IdentificationLimitExceedsCapacity,
    InvalidPreAuthLimit,
    InvalidAuthAttemptLimit,
    InvalidKeyExchangeLimit,
    InvalidKeyLifetimeLimit,
    GlobalRequestLimitExceedsCapacity,
    DecompressionLimitExceedsCapacity,
    InvalidDeadlineLimit,
};

pub const DeadlineError = error{
    DeadlinesAlreadyInitialized,
    DeadlinesNotInitialized,
    NonMonotonicTime,
};

pub const TimeoutOutcome = enum {
    Handshake,
    Authentication,
    Idle,
    TotalSession,
};

pub const DeadlineLimits = struct {
    handshake: ?u64 = null,
    authentication: ?u64 = null,
    idle: ?u64 = null,
    total_session: ?u64 = null,
};

pub const KeyLifetimeLimits = struct {
    rekey_after_encrypted_bytes: u64 = 1024 * 1024 * 1024,
    rekey_after_encrypted_packets: u64 = 1 << 30,
    rekey_after_monotonic_ticks: ?u64 = null,
};

/// The channel receive window advertised by default, matching OpenSSH.
///
/// Named because tests assert on what goes out on the wire, and a literal
/// repeated in four of them is four places to miss when it changes.
pub const default_channel_window: u32 = 2 * 1024 * 1024;

pub const ResourceCapacities = struct {
    pub const packet_size: usize = Protocol.MaxSSHPacket;
    pub const payload_size: usize = Protocol.MaxPayload;
    pub const channels: u8 = Channel.MaxChannels;
    pub const channel_window: u32 = std.math.maxInt(u32);
    pub const channel_packet_size: u32 = Protocol.MaxChannelDataLen;
    pub const channel_buffered_data: usize = Protocol.MaxChannelDataLen;
    pub const pending_buffered_data: usize = Channel.MaxPendingChannelData;
    pub const identification_lines: u16 = Protocol.MaxPreIdentificationLines;
    pub const identification_bytes: usize =
        Protocol.MaxIdentificationLineLen * (Protocol.MaxPreIdentificationLines + 1);
    pub const pre_auth_packets: u32 = 1_000_000;
    pub const pre_auth_work: u32 = 1_000_000;
    pub const server_auth_attempts: u16 = 1024;
    pub const key_exchanges: u16 = 1024;
    pub const rekey_spacing_packets: u32 = 1_000_000;
    pub const encrypted_bytes_per_key: u64 = Protocol.AesCtrT.max_bytes_per_key;
    pub const packets_per_sequence: u64 = std.math.maxInt(u32);
    pub const rekey_reserve_packets: u64 = 5;
    pub const rekey_after_encrypted_bytes: u64 = 1024 * 1024 * 1024;
    pub const rekey_after_encrypted_packets: u64 = 1 << 30;
    pub const outstanding_global_requests: u8 = 1;
    pub const decompressed_payload_size: usize = Protocol.MaxPayload;
};

pub const ResourceLimits = struct {
    max_packet_size: usize = ResourceCapacities.packet_size,
    max_payload_size: usize = ResourceCapacities.payload_size,
    max_channels: u8 = ResourceCapacities.channels,
    /// The receive window advertised on every channel this client opens.
    ///
    /// Two megabytes, which is what OpenSSH advertises. The obvious value is
    /// one maximum-size packet, and it is the wrong one: it lets a peer send
    /// exactly one packet before it must stop and wait to be credited, so
    /// every packet of a large transfer depends on a window adjustment
    /// arriving in time. A bulk download then spends its life in the one path
    /// that has to be perfect, rather than in the one that is simply fast.
    initial_channel_window: u32 = default_channel_window,
    max_channel_window: u32 = ResourceCapacities.channel_window,
    channel_packet_size: u32 = Protocol.MaxChannelDataLen,
    max_peer_packet_size: u32 = Protocol.MaxChannelDataLen,
    max_channel_buffered_data: usize = ResourceCapacities.channel_buffered_data,
    max_pending_buffered_data: usize = ResourceCapacities.pending_buffered_data,
    max_identification_lines: u16 = Protocol.MaxPreIdentificationLines,
    max_identification_bytes: usize = ResourceCapacities.identification_bytes,
    max_pre_auth_packets: u32 = 256,
    max_pre_auth_work: u32 = 1024,
    max_server_auth_attempts: u16 = 8,
    max_key_exchanges: u16 = 8,
    min_packets_between_rekeys: u32 = 0,
    max_outstanding_global_requests: u8 = 1,
    max_decompressed_payload_size: usize = ResourceCapacities.decompressed_payload_size,
    deadlines: DeadlineLimits = .{},
    key_lifetime: KeyLifetimeLimits = .{},

    pub fn validate(self: ResourceLimits) ResourceLimitConfigError!void {
        if (self.max_packet_size == 0 or self.max_packet_size > ResourceCapacities.packet_size)
            return error.PacketLimitExceedsCapacity;
        if (self.max_payload_size == 0 or self.max_payload_size > ResourceCapacities.payload_size)
            return error.PayloadLimitExceedsCapacity;
        const framing_overhead = Protocol.sizeof_PktHdr + 4 + Protocol.mac_algo.key_length;
        if (self.max_packet_size <= framing_overhead or
            self.max_payload_size > self.max_packet_size - framing_overhead)
            return error.InvalidPacketPayloadLimits;
        if (self.max_channels == 0 or self.max_channels > ResourceCapacities.channels)
            return error.ChannelLimitExceedsCapacity;
        if (self.initial_channel_window == 0 or self.initial_channel_window > self.max_channel_window)
            return error.InvalidChannelWindowLimits;
        if (self.channel_packet_size == 0 or
            self.channel_packet_size > ResourceCapacities.channel_packet_size or
            self.channel_packet_size > self.initial_channel_window)
            return error.InvalidPeerPacketLimit;
        if (self.max_peer_packet_size == 0 or self.max_peer_packet_size > ResourceCapacities.channel_packet_size)
            return error.InvalidPeerPacketLimit;
        if (self.max_channel_buffered_data == 0 or
            self.max_channel_buffered_data > ResourceCapacities.channel_buffered_data)
            return error.BufferedDataLimitExceedsCapacity;
        if (self.max_pending_buffered_data < self.max_channel_buffered_data or
            self.max_pending_buffered_data > ResourceCapacities.pending_buffered_data)
            return error.InvalidPendingDataLimit;
        if (self.max_identification_lines > ResourceCapacities.identification_lines or
            self.max_identification_bytes == 0 or
            self.max_identification_bytes > ResourceCapacities.identification_bytes)
            return error.IdentificationLimitExceedsCapacity;
        if (self.max_pre_auth_packets == 0 or self.max_pre_auth_packets > ResourceCapacities.pre_auth_packets or
            self.max_pre_auth_work == 0 or self.max_pre_auth_work > ResourceCapacities.pre_auth_work)
            return error.InvalidPreAuthLimit;
        if (self.max_server_auth_attempts == 0 or
            self.max_server_auth_attempts > ResourceCapacities.server_auth_attempts)
            return error.InvalidAuthAttemptLimit;
        if (self.max_key_exchanges == 0 or
            self.max_key_exchanges > ResourceCapacities.key_exchanges or
            self.min_packets_between_rekeys > ResourceCapacities.rekey_spacing_packets)
            return error.InvalidKeyExchangeLimit;
        const byte_reserve = std.math.mul(
            u64,
            self.max_packet_size,
            ResourceCapacities.rekey_reserve_packets,
        ) catch return error.InvalidKeyLifetimeLimit;
        if (self.key_lifetime.rekey_after_encrypted_bytes == 0 or
            self.key_lifetime.rekey_after_encrypted_bytes >
                ResourceCapacities.rekey_after_encrypted_bytes or
            self.key_lifetime.rekey_after_encrypted_bytes >
                ResourceCapacities.encrypted_bytes_per_key - byte_reserve or
            self.key_lifetime.rekey_after_encrypted_packets == 0 or
            self.key_lifetime.rekey_after_encrypted_packets >
                ResourceCapacities.rekey_after_encrypted_packets or
            self.key_lifetime.rekey_after_encrypted_packets >
                ResourceCapacities.packets_per_sequence - ResourceCapacities.rekey_reserve_packets)
            return error.InvalidKeyLifetimeLimit;
        if (self.key_lifetime.rekey_after_monotonic_ticks) |duration| {
            if (duration == 0) return error.InvalidKeyLifetimeLimit;
        }
        if (self.max_outstanding_global_requests == 0 or
            self.max_outstanding_global_requests > ResourceCapacities.outstanding_global_requests)
            return error.GlobalRequestLimitExceedsCapacity;
        if (self.max_decompressed_payload_size == 0 or
            self.max_decompressed_payload_size > ResourceCapacities.decompressed_payload_size or
            self.max_decompressed_payload_size > self.max_payload_size or
            self.channel_packet_size > self.max_decompressed_payload_size -| Protocol.ChannelExtendedDataFramingLen)
            return error.DecompressionLimitExceedsCapacity;
        if (Protocol.zlibSyncFlushBound(self.channel_packet_size + Protocol.ChannelExtendedDataFramingLen) >
            self.max_payload_size)
            return error.InvalidPeerPacketLimit;
        inline for (std.meta.fields(DeadlineLimits)) |field| {
            if (@field(self.deadlines, field.name)) |duration| {
                if (duration == 0) return error.InvalidDeadlineLimit;
            }
        }
    }

    pub fn channelLimits(self: ResourceLimits) Channel.ChannelLimits {
        return .{
            .max_channels = self.max_channels,
            .initial_window = self.initial_channel_window,
            .max_window = self.max_channel_window,
            .packet_size = self.channel_packet_size,
            .max_buffered_data = self.max_channel_buffered_data,
        };
    }
};

pub const KeyEpochStatus = struct {
    epoch: u64,
    encrypted_bytes: u64,
    encrypted_packets: u64,
    next_sequence_number: u32,
    activated_at_monotonic_tick: ?u64,
    age_monotonic_ticks: ?u64,
};

pub const KeyLifetimeStatus = struct {
    inbound: KeyEpochStatus,
    outbound: KeyEpochStatus,
    local_rekey_pending: bool,
    rekey_in_progress: bool,
};

pub const IdentificationInputError = error{
    noEOLFound,
    UnexpectedResponse,
};

pub const PacketInputError = error{
    notEnoughData,
    InvalidPacketSize,
    InvalidMac,
};

pub const MessageInputError = BufferError || error{
    UnsupportedMessage,
};

pub const EcdhInputError = BufferError || error{
    UnexpectedResponse,
};

pub const MacInputError = error{
    InvalidMac,
};

pub const TransportLimits = struct {
    pub const packet_header_len = Protocol.sizeof_PktHdr;
    pub const max_packet_len = Protocol.MaxSSHPacket;
    pub const max_payload_len = Protocol.MaxPayload;
    pub const max_identification_line_len = Protocol.MaxIdentificationLineLen;
    pub const cipher_block_len = Protocol.AesCtrT.block_size;
    pub const mac_len = Protocol.mac_algo.key_length;
    pub const ecdh_public_key_len = Protocol.kex_algo.public_length;
};

pub const CompressionAlgorithm = Protocol.CompressionAlgorithm;
pub const CompressionState = Protocol.CompressionState;

pub const PacketFrame = struct {
    packet_len: usize,
    payload_offset: usize,
    payload_len: usize,
    padding_len: u8,
    mac_offset: ?usize,
};

pub fn inspectIdentificationLine(line: []const u8) IdentificationInputError![]const u8 {
    if (line.len == 0 or line.len > Protocol.MaxIdentificationLineLen or line[line.len - 1] != '\n') {
        return error.noEOLFound;
    }
    const terminator_len: usize = if (line.len >= 2 and line[line.len - 2] == '\r') 2 else 1;
    const identification = line[0 .. line.len - terminator_len];
    if (!Protocol.isValidIdentification(identification)) return error.UnexpectedResponse;
    return identification;
}

pub fn inspectPacketHeader(packet: []const u8, encrypted: bool) PacketInputError!PacketFrame {
    return inspectPacketHeaderWithLimits(
        packet,
        encrypted,
        Protocol.MaxSSHPacket,
        Protocol.MaxPayload,
    );
}

fn inspectPacketHeaderWithLimits(
    packet: []const u8,
    encrypted: bool,
    max_packet_size: usize,
    max_payload_size: usize,
) PacketInputError!PacketFrame {
    if (packet.len < Protocol.sizeof_PktHdr) return error.notEnoughData;

    const hdr = Protocol.readPktHdr(packet[0..Protocol.sizeof_PktHdr]);
    if (hdr.padding_length < 4 or hdr.packet_length < @as(u32, hdr.padding_length) + 1) {
        return error.InvalidPacketSize;
    }

    const payload_len: usize = @intCast(hdr.packet_length - @as(u32, hdr.padding_length) - 1);
    if (payload_len > max_payload_size) return error.InvalidPacketSize;
    const packet_len: usize = 4 + @as(usize, hdr.packet_length);
    const wire_len = packet_len + if (encrypted) @as(usize, Protocol.mac_algo.key_length) else 0;
    if (wire_len > max_packet_size) return error.InvalidPacketSize;
    if (encrypted and packet_len % Protocol.AesCtrT.block_size != 0) {
        return error.InvalidPacketSize;
    }

    return .{
        .packet_len = packet_len,
        .payload_offset = Protocol.sizeof_PktHdr,
        .payload_len = payload_len,
        .padding_len = hdr.padding_length,
        .mac_offset = if (encrypted) packet_len else null,
    };
}

pub fn inspectPacket(packet: []const u8, encrypted: bool) PacketInputError!PacketFrame {
    return inspectPacketWithLimits(packet, encrypted, Protocol.MaxSSHPacket, Protocol.MaxPayload);
}

fn inspectPacketWithLimits(
    packet: []const u8,
    encrypted: bool,
    max_packet_size: usize,
    max_payload_size: usize,
) PacketInputError!PacketFrame {
    const frame = try inspectPacketHeaderWithLimits(packet, encrypted, max_packet_size, max_payload_size);
    if (packet.len < frame.packet_len) return error.notEnoughData;

    if (encrypted) {
        const expected_len = frame.packet_len + Protocol.mac_algo.key_length;
        if (packet.len < expected_len) return error.InvalidMac;
        if (packet.len != expected_len) return error.InvalidPacketSize;
    } else if (packet.len != frame.packet_len) {
        return error.InvalidPacketSize;
    }
    return frame;
}

pub fn inspectMessageFraming(payload: []const u8) MessageInputError!void {
    var reader = BufferReader.init(payload);
    const message_id = try reader.readU8();
    inline for (std.meta.tags(Protocol.MsgId)) |known| {
        if (message_id == @intFromEnum(known)) return;
    }
    return error.UnsupportedMessage;
}

pub fn inspectEcdhPublicKeyString(encoded: []const u8) EcdhInputError!void {
    var reader = BufferReader.init(encoded);
    const public_key = try reader.readU32LenString();
    if (public_key.len != Protocol.kex_algo.public_length or reader.off != reader.payload.len) {
        return error.UnexpectedResponse;
    }
}

pub fn exerciseEcdhReplyPublicKey(public_key: []const u8, allocator: std.mem.Allocator) SshzError!void {
    var prng = std.Random.DefaultPrng.init(0x60);
    var client = try SshzClient.init(prng.random(), "malformed-corpus", allocator);
    defer client.deinit();

    var payload_backing: [128]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY));
    try payload.writeU32LenString("");
    try payload.writeU32LenString(public_key);
    try payload.writeU32LenString("");

    var packet_random = prng.random();
    const packet = try Protocol.wrapPayload(
        &packet_random,
        false,
        &client.session.keydata.s2c,
        payload.active(),
        &client.iobuf_rd,
    );
    client.session.setSessionState(.EcdhReply);
    try client.session.handlePacket(packet, &client);
}

pub fn verifyPacketMac(calculated: [Protocol.mac_algo.key_length]u8, received: []const u8) MacInputError!void {
    const mac_length = Protocol.mac_algo.key_length;
    if (received.len != mac_length) return error.InvalidMac;
    if (!std.crypto.timing_safe.eql([mac_length]u8, calculated, received[0..mac_length].*)) {
        return error.InvalidMac;
    }
}

pub const DisconnectReason = struct {
    code: u32,
    description: []const u8,
};

pub const AuthMethod = enum {
    None,
    PublicKey,
    Password,
    KeyboardInteractive,

    pub fn name(self: AuthMethod) []const u8 {
        return switch (self) {
            .None => "none",
            .PublicKey => "publickey",
            .Password => "password",
            .KeyboardInteractive => "keyboard-interactive",
        };
    }

    pub fn fromName(method_name: []const u8) ?AuthMethod {
        inline for (std.meta.tags(AuthMethod)) |method| {
            if (std.mem.eql(u8, method_name, method.name())) return method;
        }
        return null;
    }
};

pub const AuthFailureInfo = struct {
    pub const MaxSupportedMethods = std.meta.tags(AuthMethod).len;
    pub const MaxUnsupportedMethodsLen = 128;

    attempted_method: AuthMethod,
    supported_methods: [MaxSupportedMethods]AuthMethod = .{.None} ** MaxSupportedMethods,
    supported_methods_len: u8 = 0,
    unsupported_methods: [MaxUnsupportedMethodsLen]u8 = .{0} ** MaxUnsupportedMethodsLen,
    unsupported_methods_len: u8 = 0,
    partial_success: bool,
    auth_stage: u8,

    pub fn parse(
        attempted_method: AuthMethod,
        method_names: []const u8,
        partial_success: bool,
        auth_stage: u8,
    ) AuthFailureInfo {
        var info: AuthFailureInfo = .{
            .attempted_method = attempted_method,
            .partial_success = partial_success,
            .auth_stage = auth_stage,
        };
        var iter = std.mem.splitSequence(u8, method_names, ",");
        while (iter.next()) |name| {
            if (name.len == 0) continue;
            if (AuthMethod.fromName(name)) |method| {
                if (!info.hasMethod(method) and info.supported_methods_len < MaxSupportedMethods) {
                    info.supported_methods[info.supported_methods_len] = method;
                    info.supported_methods_len += 1;
                }
            } else {
                info.appendUnsupportedMethod(name);
            }
        }
        return info;
    }

    pub fn supportedMethods(self: *const AuthFailureInfo) []const AuthMethod {
        return self.supported_methods[0..self.supported_methods_len];
    }

    pub fn unsupportedMethodNames(self: *const AuthFailureInfo) []const u8 {
        return self.unsupported_methods[0..self.unsupported_methods_len];
    }

    pub fn hasMethod(self: *const AuthFailureInfo, method: AuthMethod) bool {
        for (self.supportedMethods()) |supported| {
            if (supported == method) return true;
        }
        return false;
    }

    fn appendUnsupportedMethod(self: *AuthFailureInfo, name: []const u8) void {
        var offset: usize = self.unsupported_methods_len;
        if (offset != 0) {
            if (offset + 1 >= self.unsupported_methods.len) return;
            self.unsupported_methods[offset] = ',';
            offset += 1;
        }
        const copy_len = @min(name.len, self.unsupported_methods.len - offset);
        @memcpy(self.unsupported_methods[offset .. offset + copy_len], name[0..copy_len]);
        self.unsupported_methods_len = @intCast(offset + copy_len);
    }
};

pub const EndSessionReason = union(enum) {
    Disconnect,
    ServerDisconnect: DisconnectReason,
    AuthFailure: AuthFailureInfo,
    HostKeyRejected: HostKeyInfo,
};

pub const Role = enum {
    Client,
    Server,
};

fn sessionType(role: Role) type {
    return switch (role) {
        .Client => ClientSession,
        .Server => ServerSession,
    };
}

fn eventCodeType(role: Role) type {
    return switch (role) {
        .Client => SshzClientEventCodes,
        .Server => SshzServerEventCodes,
    };
}

pub const KeyboardInteractivePrompt = struct {
    name: []const u8,
    instruction: []const u8,
    prompt: []const u8,
    echo: bool,
};

pub const HostKeyInfo = struct {
    raw_key: ?[]const u8,
    fingerprint: [Protocol.hash_algo.digest_length]u8,

    pub fn fingerprintStr(self: *const HostKeyInfo, buf: *[44]u8) []const u8 {
        return std.base64.standard.Encoder.encode(buf, &self.fingerprint);
    }
};

pub const SshzClientEventCodes = union(enum) {
    ServerIdentification: []const u8,
    CheckHostKey: HostKeyInfo,
    AuthMethodStarted: AuthMethod,
    GetPrivateKey,
    GetKeyPassphrase,
    GetAuthPassphrase,
    EndSession: EndSessionReason,
    Connected,
    ChannelOpened: u32,
    ChannelOpenFailure: ChannelOpenFailure,
    /// The peer ended its data direction for this non-agent channel.
    ChannelEof: u32,
    /// The close handshake completed. Clearing this event releases the slot.
    ChannelClosed: u32,
    ChannelOpenRequest: ChannelOpenRequestEvent,
    TcpipForwardSuccess: TcpipForwardSuccess,
    TcpipForwardFailure: TcpipForwardFailure,
    CancelTcpipForwardSuccess: TcpipForwardRequest,
    CancelTcpipForwardFailure: TcpipForwardRequest,
    // The channel is part of the event because a client can have more than
    // one open at a time -- the auto-shell session and any `direct-tcpip`
    // tunnel -- and their bytes are not interchangeable. Splicing one into
    // the other corrupts whatever protocol is running over the tunnel, and
    // does so silently. These match the server-side events, which have
    // always carried the channel.
    RxData: ChannelData,
    RxExtendedData: ChannelExtendedData,
    AgentChannelOpen: u32,
    AgentData: ChannelData,
    AgentChannelClosed: u32,
    Banner: []const u8,
    KeyboardInteractive: KeyboardInteractivePrompt,
};

pub const SshOpenFailureReason = struct {
    pub const AdministrativelyProhibited: u32 = 1;
    pub const ConnectFailed: u32 = 2;
    pub const UnknownChannelType: u32 = 3;
    pub const ResourceShortage: u32 = 4;
};

pub const ChannelOpenFailure = struct {
    channel: u32,
    reason_code: u32,
    description: []const u8,
};

pub const ChannelExitSignal = struct {
    signal_name: []const u8,
    core_dumped: bool,
    error_message: []const u8,
    language_tag: []const u8,
};

pub const ChannelExitResult = union(enum) {
    Status: u32,
    Signal: ChannelExitSignal,
    /// The channel completed its close exchange without a terminal result.
    NoResult,
};

pub const TcpipForwardRequest = struct {
    bind_address: []const u8,
    bind_port: u32,
};

pub const TcpipForwardSuccess = struct {
    bind_address: []const u8,
    requested_port: u32,
    bound_port: u32,
};

pub const TcpipForwardFailure = struct {
    bind_address: []const u8,
    bind_port: u32,
};

/// Value-owned identifier, valid only with the client that issued it.
/// Tokens are never reused during that client's lifetime.
pub const KeepaliveToken = struct {
    id: u64,
};

pub const KeepaliveTransmission = enum {
    /// Accepted locally, but not yet framed. May wait behind output or rekey.
    Queued,
    /// Framed; some or none of its bytes have been consumed by the caller.
    Emitting,
    /// Every byte of the request has passed through `consumed`.
    /// A buffering transport may still have unsent bytes.
    HandedToTransport,
};

/// Either reply proves peer responsiveness, not remote application progress.
pub const KeepaliveReply = enum { Success, Failure };

pub const KeepaliveOutcome = union(enum) {
    Pending,
    Acknowledged: KeepaliveReply,
    Cancelled,
    Disconnected,
};

/// Contains no borrowed storage; copies survive event clearing and teardown.
pub const KeepaliveStatus = struct {
    token: KeepaliveToken,
    transmission: KeepaliveTransmission = .Queued,
    /// Set only by the caller through `markKeepaliveFlushed`, never by enqueue.
    transport_flushed: bool = false,
    outcome: KeepaliveOutcome = .Pending,
};

pub const DirectTcpipOpen = struct {
    host: []const u8,
    port: u32,
    originator_host: []const u8,
    originator_port: u32,
};

pub const ForwardedTcpipOpen = struct {
    connected_host: []const u8,
    connected_port: u32,
    originator_host: []const u8,
    originator_port: u32,
};

pub const ChannelOpenRequestType = union(enum) {
    Session,
    DirectTcpip: DirectTcpipOpen,
    ForwardedTcpip: ForwardedTcpipOpen,
};

pub const ChannelOpenRequestEvent = struct {
    channel: u32,
    request: ChannelOpenRequestType,
};

pub const ExtendedData = struct {
    data_type: u32,
    data: []const u8,
};

pub const UserAuthAttempt = union(enum) {
    Password: []const u8,
    Pubkey: PublicKeyIdentity,
};

pub const UserCredentialsPasswordOrPubkey = UserAuthAttempt;

pub const PublicKeyIdentity = struct {
    algorithm: []const u8,
    blob: []const u8,
};

pub const UserCredentials = struct {
    username: []const u8,
    auth: ?UserAuthAttempt, // null for "none" auth

    pub fn method(self: UserCredentials) AuthMethod {
        const attempt = self.auth orelse return .None;
        return switch (attempt) {
            .Password => .Password,
            .Pubkey => .PublicKey,
        };
    }
};

pub const AuthorizationDecision = enum {
    Deny,
    Allow,
};

pub fn validateUserPublicKeyBlob(blob: []const u8) SshzError!void {
    _ = try Key.parsePublicKeyBlob(blob);
}

pub const ChannelRequestType = union(enum) {
    Shell,
    Exec: []const u8,
    Subsystem: []const u8,
    Env: struct { name: []const u8, value: []const u8 },
    AgentForward,
};

pub const ChannelRequestEvent = struct {
    /// Server events are emitted only for an accepted `Session` channel.
    channel: u32,
    request: ChannelRequestType,
};

pub const WindowSize = struct {
    /// Server events are emitted only for an accepted `Session` channel.
    channel: u32,
    cols: u32,
    rows: u32,
    width_px: u32,
    height_px: u32,
};

pub const ChannelSignal = struct {
    /// Server events are emitted only for an accepted `Session` channel.
    channel: u32,
    name: []const u8,
};

pub const ChannelData = struct {
    channel: u32,
    data: []const u8,
};

pub const ChannelExtendedData = struct {
    channel: u32,
    data_type: u32,
    data: []const u8,
};

pub const SshzServerEventCodes = union(enum) {
    EndSession: EndSessionReason,
    UserAuth: UserCredentials,
    GetPubkeyForUser: []const u8,
    Connected: u32,
    ChannelOpened: u32,
    ChannelOpenFailure: ChannelOpenFailure,
    AgentChannelOpen: u32,
    AgentChannelClosed: u32,
    RxData: ChannelData,
    RxExtendedData: ChannelExtendedData,
    WindowChange: WindowSize,
    Signal: ChannelSignal,
    ChannelRequest: ChannelRequestEvent,
    ChannelOpenRequest: ChannelOpenRequestEvent,
    TcpipForward: TcpipForwardRequest,
    CancelTcpipForward: TcpipForwardRequest,
};

pub fn SshzEvent(role: Role) type {
    return union(enum) {
        Event: eventCodeType(role),
        ReadyToConsume: usize,
        ReadyToProduce: usize,
        ReadyToConsumeAndProduce: struct { consume: usize, produce: usize },
    };
}

// Producing a block, or consuming a block
pub fn IoAction(role: Role) type {
    return union(enum) {
        Producing: usize,
        Consuming: usize,
        Eventing: eventCodeType(role),
    };
}

// An IoAction, followed by state to move Session to on completion
pub fn IoStep(role: Role) type {
    return struct {
        action: IoAction(role),
        next_state: Protocol.IoSessionState,
    };
}

// Either Idle, or Active (Producing or Consuming) with a next IoSessionState on completion
pub fn IoState(role: Role) type {
    return union(enum) {
        Idle,
        Active: IoStep(role),
    };
}

pub const SshzClient = SshzImpl(.Client);
pub const SshzServer = SshzImpl(.Server);

const DeadlinePhase = enum {
    Handshake,
    Authentication,
    Active,
};

const DeadlineState = struct {
    initialized: bool = false,
    started_at: u64 = 0,
    phase_started_at: u64 = 0,
    last_activity_at: u64 = 0,
    last_observed_at: u64 = 0,
    phase: DeadlinePhase = .Handshake,
    timeout: ?TimeoutOutcome = null,
};

pub fn SshzImpl(role: Role) type {
    return struct {
        const Self = @This();

        session: sessionType(role),
        iostate_rd: IoState(role),
        iostate_wr: IoState(role),

        // Session-owned packet storage. Event slices borrow these buffers and
        // remain valid only until the event is cleared or another API call
        // documented to release the event is made.
        iobuf_rd: [Protocol.MaxSSHPacket]u8 = .{0} ** Protocol.MaxSSHPacket,
        iobuf_wr: [Protocol.MaxSSHPacket]u8 = .{0} ** Protocol.MaxSSHPacket,
        iobuf_decompressed: [Protocol.MaxPayload]u8 = .{0} ** Protocol.MaxPayload,
        rd_nbytes: usize,
        rd_off: usize,
        wr_nbytes: usize,
        wr_off: usize,
        limits: ResourceLimits,
        identification_bytes: usize,
        pre_auth_packets: u32,
        pre_auth_work: u32,
        server_auth_attempts: u16,
        key_exchanges: u16,
        packets_received: u64,
        last_kex_packet: ?u64,
        deadline_state: DeadlineState,
        local_rekey_pending: bool,
        terminated: bool,

        pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
            return initWithLimits(rand, username, allocator, .{});
        }

        pub fn initWithLimits(
            rand: std.Random,
            username: []const u8,
            allocator: std.mem.Allocator,
            limits: ResourceLimits,
        ) !Self {
            try limits.validate();
            return Self{
                .session = try sessionType(role).initWithLimits(rand, username, allocator, limits),
                .rd_nbytes = 0,
                .rd_off = 0,
                .wr_nbytes = 0,
                .wr_off = 0,
                .iostate_rd = .Idle,
                .iostate_wr = .Idle,
                .limits = limits,
                .identification_bytes = 0,
                .pre_auth_packets = 0,
                .pre_auth_work = 0,
                .server_auth_attempts = 0,
                .key_exchanges = 0,
                .packets_received = 0,
                .last_kex_packet = null,
                .deadline_state = .{},
                .local_rekey_pending = false,
                .terminated = false,
            };
        }

        pub fn deinit(self: *Self) void {
            self.terminated = true;
            self.iostate_rd = .Idle;
            self.iostate_wr = .Idle;
            self.local_rekey_pending = false;
            self.session.deinit();
            std.crypto.secureZero(u8, &self.iobuf_rd);
            std.crypto.secureZero(u8, &self.iobuf_wr);
            std.crypto.secureZero(u8, &self.iobuf_decompressed);
            self.rd_nbytes = 0;
            self.rd_off = 0;
            self.wr_nbytes = 0;
            self.wr_off = 0;
        }

        fn currentDeadlinePhase(self: *const Self) DeadlinePhase {
            return switch (role) {
                .Client => switch (self.session.sessionState) {
                    .AuthServReq,
                    .AuthServRsp,
                    .AuthStart,
                    .NoneAuthReq,
                    .GetPrivateKeyCompleted,
                    .PubkeyAuthDecodeKeyPasswordless,
                    .PubkeyAuthDecodeKeyPassword,
                    .PubkeyAuthStart,
                    .PubkeyAuthReq,
                    .AuthMethodQueued,
                    .AuthRsp,
                    .PasswordAuthStart,
                    .PasswordAuthReq,
                    .KeyboardInteractiveAuthStart,
                    .KeyboardInteractiveAuthReq,
                    .KeyboardInteractiveInfoRsp,
                    => .Authentication,
                    .ChannelOpenReq, .ChannelOpenRsp, .ChannelActive => .Active,
                    else => .Handshake,
                },
                .Server => switch (self.session.sessionState) {
                    .AuthRead,
                    .AuthRspServReqSuccess,
                    .CheckUserPasswordAuth,
                    .UserAuthDenied,
                    .UserAuthAccepted,
                    .AuthPkAllowed,
                    => .Authentication,
                    .Authenticated, .ChannelActive => .Active,
                    else => .Handshake,
                },
            };
        }

        fn observeMonotonic(self: *Self, now: u64) DeadlineError!void {
            if (!self.deadline_state.initialized) return error.DeadlinesNotInitialized;
            if (now < self.deadline_state.last_observed_at) return error.NonMonotonicTime;
            self.deadline_state.last_observed_at = now;
        }

        pub fn initializeDeadlines(self: *Self, now: u64) DeadlineError!void {
            if (self.deadline_state.initialized) return error.DeadlinesAlreadyInitialized;
            const phase = self.currentDeadlinePhase();
            self.deadline_state = .{
                .initialized = true,
                .started_at = now,
                .phase_started_at = now,
                .last_activity_at = now,
                .last_observed_at = now,
                .phase = phase,
            };
            if (self.session.inbound_encrypted) {
                const inkeys = self.inboundKeyData();
                if (inkeys.activated_at_monotonic_tick == null)
                    inkeys.activated_at_monotonic_tick = now;
            }
            if (self.session.encrypted) {
                const outkeys = self.outboundKeyData();
                if (outkeys.activated_at_monotonic_tick == null)
                    outkeys.activated_at_monotonic_tick = now;
            }
        }

        pub fn noteActivity(self: *Self, now: u64) DeadlineError!void {
            try self.observeMonotonic(now);
            self.deadline_state.last_activity_at = now;
        }

        fn expired(now: u64, since: u64, limit: ?u64) bool {
            return if (limit) |duration| now - since >= duration else false;
        }

        pub fn checkDeadlines(self: *Self, now: u64) DeadlineError!?TimeoutOutcome {
            try self.observeMonotonic(now);
            if (self.deadline_state.timeout) |outcome| return outcome;

            if (expired(now, self.deadline_state.started_at, self.limits.deadlines.total_session))
                return .TotalSession;
            if (expired(now, self.deadline_state.last_activity_at, self.limits.deadlines.idle))
                return .Idle;

            const phase = self.currentDeadlinePhase();
            if (phase != self.deadline_state.phase) {
                self.deadline_state.phase = phase;
                self.deadline_state.phase_started_at = now;
            }
            const phase_limit = switch (phase) {
                .Handshake => self.limits.deadlines.handshake,
                .Authentication => self.limits.deadlines.authentication,
                .Active => null,
            };
            if (expired(now, self.deadline_state.phase_started_at, phase_limit)) {
                return switch (phase) {
                    .Handshake => .Handshake,
                    .Authentication => .Authentication,
                    .Active => unreachable,
                };
            }
            return null;
        }

        pub fn tick(self: *Self, now: u64) DeadlineError!?TimeoutOutcome {
            const outcome = try self.checkDeadlines(now);
            if (outcome) |timed_out| {
                self.deadline_state.timeout = timed_out;
                self.failClosed();
            } else {
                self.updateLocalRekeyPending(now);
                _ = self.maybeStartLocalRekey();
            }
            return outcome;
        }

        pub fn timeoutOutcome(self: *const Self) ?TimeoutOutcome {
            return self.deadline_state.timeout;
        }

        fn inboundKeyData(self: *Self) *Protocol.KeyDataUni {
            return switch (role) {
                .Client => &self.session.keydata.s2c,
                .Server => &self.session.keydata.c2s,
            };
        }

        fn outboundKeyData(self: *Self) *Protocol.KeyDataUni {
            return switch (role) {
                .Client => &self.session.keydata.c2s,
                .Server => &self.session.keydata.s2c,
            };
        }

        pub fn keyActivationTime(self: *const Self) ?u64 {
            return if (self.deadline_state.initialized)
                self.deadline_state.last_observed_at
            else
                null;
        }

        fn keyUsageDue(self: *const Self, keys: *const Protocol.KeyDataUni, now: ?u64) bool {
            if (keys.epoch == 0) return false;
            if (keys.encrypted_bytes >= self.limits.key_lifetime.rekey_after_encrypted_bytes or
                keys.encrypted_packets >= self.limits.key_lifetime.rekey_after_encrypted_packets)
                return true;
            const age_limit = self.limits.key_lifetime.rekey_after_monotonic_ticks orelse return false;
            const activated_at = keys.activated_at_monotonic_tick orelse return false;
            const current = now orelse return false;
            return current - activated_at >= age_limit;
        }

        fn updateLocalRekeyPending(self: *Self, now: ?u64) void {
            if (self.session.is_rekeying) {
                self.local_rekey_pending = false;
                return;
            }
            if (self.keyUsageDue(self.inboundKeyData(), now) or
                self.keyUsageDue(self.outboundKeyData(), now))
                self.local_rekey_pending = true;
        }

        fn maybeStartLocalRekey(self: *Self) bool {
            if (!self.local_rekey_pending or self.session.is_rekeying or
                !self.session.encrypted or !self.session.inbound_encrypted or
                self.iostate_rd != .Idle or self.iostate_wr != .Idle)
                return false;
            switch (self.session.ioSessionState) {
                .Idle, .ReadPktHdr => {},
                else => return false,
            }
            self.session.startLocalRekey();
            self.local_rekey_pending = false;
            return true;
        }

        fn epochStatus(self: *const Self, keys: *const Protocol.KeyDataUni) KeyEpochStatus {
            const age = if (self.deadline_state.initialized and
                keys.activated_at_monotonic_tick != null)
                self.deadline_state.last_observed_at - keys.activated_at_monotonic_tick.?
            else
                null;
            return .{
                .epoch = keys.epoch,
                .encrypted_bytes = keys.encrypted_bytes,
                .encrypted_packets = keys.encrypted_packets,
                .next_sequence_number = keys.seq,
                .activated_at_monotonic_tick = keys.activated_at_monotonic_tick,
                .age_monotonic_ticks = age,
            };
        }

        pub fn keyLifetimeStatus(self: *const Self) KeyLifetimeStatus {
            const inbound = switch (role) {
                .Client => &self.session.keydata.s2c,
                .Server => &self.session.keydata.c2s,
            };
            const outbound = switch (role) {
                .Client => &self.session.keydata.c2s,
                .Server => &self.session.keydata.s2c,
            };
            return .{
                .inbound = self.epochStatus(inbound),
                .outbound = self.epochStatus(outbound),
                .local_rekey_pending = self.local_rekey_pending,
                .rekey_in_progress = self.session.is_rekeying,
            };
        }

        fn gateApplicationInitiation(self: *Self) SshzError!void {
            self.updateLocalRekeyPending(null);
            _ = self.maybeStartLocalRekey();
            if (self.local_rekey_pending or self.session.is_rekeying) return IoError.NotReady;
        }

        fn latchKeyLifetimeError(self: *Self, err: SshzError) void {
            if (err == IoError.KeyLifetimeExceeded) self.failClosed();
        }

        fn failClosed(self: *Self) void {
            if (self.terminated) return;
            self.terminated = true;
            self.iostate_rd = .Idle;
            self.iostate_wr = .Idle;
            self.rd_nbytes = 0;
            self.rd_off = 0;
            self.wr_nbytes = 0;
            self.wr_off = 0;
            self.local_rekey_pending = false;
            std.crypto.secureZero(u8, &self.iobuf_rd);
            std.crypto.secureZero(u8, &self.iobuf_wr);
            std.crypto.secureZero(u8, &self.iobuf_decompressed);
            self.session.failClosed();
        }

        fn scrubReceiveBuffers(self: *Self) void {
            std.crypto.secureZero(u8, &self.iobuf_rd);
            std.crypto.secureZero(u8, &self.iobuf_decompressed);
            self.rd_nbytes = 0;
            self.rd_off = 0;
        }

        pub fn accountInboundMessage(self: *Self, msgid: u8) SshzError!void {
            if (self.terminated) return IoError.SessionTerminated;
            if (self.packets_received == std.math.maxInt(u64)) {
                self.failClosed();
                return IoError.ResourceLimitExceeded;
            }
            self.packets_received += 1;

            if (self.currentDeadlinePhase() != .Active) {
                if (self.pre_auth_packets >= self.limits.max_pre_auth_packets) {
                    self.failClosed();
                    return IoError.TooManyPreAuthPackets;
                }
                self.pre_auth_packets += 1;
                const work: u32 = switch (msgid) {
                    @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT),
                    @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT),
                    @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY),
                    => 8,
                    @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST) => 4,
                    else => 1,
                };
                if (work > self.limits.max_pre_auth_work -| self.pre_auth_work) {
                    self.failClosed();
                    return IoError.TooMuchPreAuthWork;
                }
                self.pre_auth_work += work;
            }

            if (msgid == @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT)) {
                if (self.key_exchanges >= self.limits.max_key_exchanges) {
                    self.failClosed();
                    return IoError.TooManyKeyExchanges;
                }
                if (self.last_kex_packet) |last| {
                    if (self.packets_received - last <= self.limits.min_packets_between_rekeys) {
                        self.failClosed();
                        return IoError.RekeyTooFrequent;
                    }
                }
                self.key_exchanges += 1;
                self.last_kex_packet = self.packets_received;
            }

            if (comptime role == .Server) {
                if (msgid == @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST)) {
                    if (self.server_auth_attempts >= self.limits.max_server_auth_attempts) {
                        self.failClosed();
                        return IoError.TooManyAuthAttempts;
                    }
                    self.server_auth_attempts += 1;
                }
            }
        }

        // for session use
        pub fn requestWrite(self: *Self, wbuf: []const u8, next_state: Protocol.IoSessionState) SshzError!void {
            if (self.terminated) return IoError.SessionTerminated;
            if (wbuf.len == 0 or wbuf.len > self.limits.max_packet_size)
                return IoError.ResourceLimitExceeded;
            std.debug.assert(self.iostate_wr == .Idle);
            std.debug.assert(&wbuf[0] == &self.iobuf_wr[0]);
            self.wr_nbytes = wbuf.len;
            self.wr_off = 0;
            self.iostate_wr = .{ .Active = .{
                .action = .{ .Producing = wbuf.len },
                .next_state = next_state,
            } };
        }

        // for session use
        pub fn requestRead(self: *Self, offset: usize, nbytes: usize, next_state: Protocol.IoSessionState) void {
            if (offset == 0) self.scrubReceiveBuffers();
            self.rd_nbytes = 0;
            self.rd_off = offset;
            self.iostate_rd = .{ .Active = .{
                .action = .{ .Consuming = nbytes },
                .next_state = next_state,
            } };
        }

        // for session use
        pub fn requestEvent(self: *Self, code: eventCodeType(role), next_state: Protocol.IoSessionState) void {
            if (role == .Client and code == .EndSession) self.session.endGlobalRequests();
            self.iostate_wr = .{ .Active = .{
                .action = .{ .Eventing = code },
                .next_state = next_state,
            } };
        }

        /// Resolves and clears the current server UserAuth event in one step.
        /// Allow accepts a public-key probe with PK_OK, but only accepts a signed
        /// public-key request as authentication. All other outcomes remain denied.
        pub fn decideUserAuth(self: *Self, decision: AuthorizationDecision) SshzError!void {
            switch (role) {
                .Client => return IoError.UnimplementedService,
                .Server => {
                    switch (self.iostate_wr) {
                        .Active => |iotype| switch (iotype.action) {
                            .Eventing => |event_code| switch (event_code) {
                                .UserAuth => {
                                    try self.session.decideAuthorization(decision);
                                    try self.clearEvent(event_code);
                                    return;
                                },
                                else => {},
                            },
                            else => {},
                        },
                        else => {},
                    }
                    return IoError.UnexpectedResponse;
                },
            }
        }

        /// Compatibility API for setting the current server UserAuth decision.
        /// The application must subsequently clear the UserAuth event.
        pub fn grantAccess(self: *Self, allow: bool) SshzError!void {
            switch (role) {
                .Client => return IoError.UnimplementedService, // FIXME something more tailored
                .Server => return try self.session.grantAccess(allow),
            }
        }

        pub fn clearEvent(self: *Self, clearEventCode: eventCodeType(role)) SshzError!void {
            TRACE(.Debug, "clearEvent tag={s}", .{@tagName(clearEventCode)});

            switch (self.iostate_wr) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Eventing => |eventCode| {
                            if (@intFromEnum(eventCode) == @intFromEnum(clearEventCode)) {
                                if (comptime role == .Client) {
                                    switch (eventCode) {
                                        .CheckHostKey => return IoError.badClearEvent,
                                        .ChannelClosed => |channel_id| {
                                            const end_session = try self.session.releaseClosedChannel(channel_id);
                                            self.session.setIoSessionState(iotype.next_state);
                                            self.iostate_wr = .Idle;
                                            self.scrubReceiveBuffers();
                                            if (end_session) {
                                                self.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
                                            } else {
                                                try self.advance();
                                            }
                                            return;
                                        },
                                        .AgentChannelClosed => {
                                            self.session.setIoSessionState(iotype.next_state);
                                            self.iostate_wr = .Idle;
                                            self.scrubReceiveBuffers();
                                            if (self.session.shouldEndAfterChannelRelease()) {
                                                self.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
                                            } else {
                                                try self.advance();
                                            }
                                            return;
                                        },
                                        else => {},
                                    }
                                }
                                if (comptime role == .Server) {
                                    switch (eventCode) {
                                        .TcpipForward, .CancelTcpipForward, .ChannelOpenRequest => return IoError.badClearEvent,
                                        .UserAuth => {
                                            if (self.session.sessionState == .CheckUserPasswordAuth) {
                                                try self.session.decideAuthorization(.Deny);
                                            }
                                        },
                                        else => {},
                                    }
                                }
                                // event succesfully cleared
                                self.session.setIoSessionState(iotype.next_state);
                                self.iostate_wr = .Idle;
                                self.scrubReceiveBuffers();
                                try self.advance();
                                return;
                            }
                        },
                        else => {},
                    }
                },
                else => {},
            }

            return IoError.badClearEvent;
        }

        pub fn getNextEvent(self: *Self) SshzError!SshzEvent(role) {
            if (self.terminated) return IoError.SessionTerminated;
            // if eventing, send an event
            switch (self.iostate_wr) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Eventing => |eventCode| {
                            return SshzEvent(role){ .Event = eventCode };
                        },
                        else => {},
                    }
                },
                else => {},
            }

            // check both read and write readiness
            var can_consume_nbytes: usize = 0;
            var can_produce_nbytes: usize = 0;

            try self.getIoReq(&can_consume_nbytes, &can_produce_nbytes);

            if (can_consume_nbytes > 0 and can_produce_nbytes > 0) {
                return SshzEvent(role){ .ReadyToConsumeAndProduce = .{ .consume = can_consume_nbytes, .produce = can_produce_nbytes } };
            } else if (can_consume_nbytes > 0) {
                return SshzEvent(role){ .ReadyToConsume = can_consume_nbytes };
            } else if (can_produce_nbytes > 0) {
                return SshzEvent(role){ .ReadyToProduce = can_produce_nbytes };
            } else {
                return IoError.NotReady;
            }
        }

        fn getIoReq(self: *Self, can_consume: *usize, can_produce: *usize) SshzError!void {
            try self.advance();

            // check read side
            can_consume.* = 0;
            switch (self.iostate_rd) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Consuming => |target_size| {
                            TRACE(.Debug, "getIoReq Consuming target_size={d} iobuf_rd.len={d} rd_nbytes={d}", .{ target_size, self.iobuf_rd.len, self.rd_nbytes });
                            if (target_size > self.iobuf_rd.len - self.rd_nbytes) {
                                can_consume.* = self.iobuf_rd.len - self.rd_nbytes;
                            } else {
                                can_consume.* = target_size - self.rd_nbytes;
                            }
                        },
                        else => {},
                    }
                },
                else => {},
            }

            // check write side
            can_produce.* = 0;
            switch (self.iostate_wr) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Producing => |block_size| {
                            _ = block_size;
                            TRACE(.Debug, "getIoReq Producing wr_nbytes={d}", .{self.wr_nbytes});
                            can_produce.* = self.wr_nbytes - self.wr_off;
                        },
                        else => {},
                    }
                },
                else => {},
            }
        }

        pub fn write(self: *Self, wbuf: []const u8) SshzError!void {
            if (self.terminated) return IoError.SessionTerminated;
            TRACE(.Debug, "sshz.write len={d} .rd_nbytes={d}", .{ wbuf.len, self.rd_nbytes });
            switch (self.iostate_rd) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Consuming => |target_size| {
                            if (wbuf.len > target_size - self.rd_nbytes) {
                                return IoError.cannotAcceptWrite;
                            }

                            @memcpy(self.iobuf_rd[self.rd_nbytes + self.rd_off .. self.rd_nbytes + wbuf.len + self.rd_off], wbuf);
                            self.rd_nbytes += wbuf.len;

                            if (self.rd_nbytes == target_size) {
                                // entire block has been written by caller
                                self.session.setIoSessionState(iotype.next_state);
                                self.iostate_rd = .Idle;
                                try self.advance();
                            }
                        },
                        else => {},
                    }
                },
                else => return IoError.cannotAcceptWrite,
            }
        }

        pub fn peek(self: *Self, nbytes: usize) SshzError![]const u8 {
            if (self.terminated) return IoError.SessionTerminated;
            TRACE(.Debug, "peek nbytes={d} .wr_off={d} .wr_nbytes={d}", .{ nbytes, self.wr_off, self.wr_nbytes });
            // sanity check
            switch (self.iostate_wr) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Producing => {}, // ok
                        else => return IoError.notProducing,
                    }
                },
                else => return IoError.notProducing,
            }

            const bytes_remaining = self.wr_nbytes - self.wr_off;

            return self.iobuf_wr[self.wr_off .. self.wr_off + @min(nbytes, bytes_remaining)];
        }

        pub fn consumed(self: *Self, nbytes: usize) SshzError!void {
            if (self.terminated) return IoError.SessionTerminated;
            TRACE(.Debug, "consumed nbytes={d} wr_off={d} .wr_nbytes={d}", .{ nbytes, self.wr_off, self.wr_nbytes });

            const bytes_remaining = self.wr_nbytes - self.wr_off;

            // sanity check
            switch (self.iostate_wr) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Producing => {
                            if (nbytes > bytes_remaining) {
                                return IoError.notEnoughData;
                            }
                        },
                        else => return IoError.notProducing,
                    }
                },
                else => return IoError.notProducing,
            }

            self.wr_off += nbytes;

            if (self.wr_off == self.wr_nbytes) {
                // entire block has been consumed by caller
                switch (self.iostate_wr) {
                    .Active => |iotype| {
                        self.iostate_wr = .Idle;
                        std.crypto.secureZero(u8, self.iobuf_wr[0..self.wr_nbytes]);
                        self.wr_nbytes = 0;
                        self.wr_off = 0;
                        switch (iotype.next_state) {
                            .GlobalRequestWriteComplete => {
                                if (role == .Client) {
                                    self.session.completeGlobalRequestWrite() catch |err| {
                                        self.failClosed();
                                        return err;
                                    };
                                }
                            },
                            .WriteCompletePreserveState => {
                                if (role == .Client) {
                                    self.session.completeChannelWindowAdjust(self) catch |err| {
                                        self.failClosed();
                                        return err;
                                    };
                                }
                            },
                            .ChannelWriteComplete => |channel_id| {
                                self.session.completeChannelWrite(channel_id, self) catch |err| {
                                    self.failClosed();
                                    return err;
                                };
                            },
                            .ChannelControlComplete => |channel_id| {
                                self.session.completeChannelControl(channel_id, self) catch |err| {
                                    self.failClosed();
                                    return err;
                                };
                            },
                            else => self.session.setIoSessionState(iotype.next_state),
                        }
                        try self.advance();
                    },
                    else => unreachable,
                }
            }
        }

        pub fn getRecvBuffer(self: *Self, iobuf: []u8, inkeys: *Protocol.KeyDataUni) SshzError!BufferReader {
            const frame = try inspectPacketWithLimits(
                iobuf,
                self.session.inbound_encrypted,
                self.limits.max_packet_size,
                self.limits.max_payload_size,
            );
            const payload_len = frame.payload_len;
            const pkt_len = frame.packet_len;
            const payload = iobuf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];

            if (!self.session.inbound_encrypted) {
                const decompressed = try inkeys.compression.decompressPayload(
                    payload,
                    self.iobuf_decompressed[0..self.limits.max_decompressed_payload_size],
                );
                return BufferReader.init(decompressed);
            } else {
                UNSAFE_TRACEDUMP(.Debug, "all buf", .{}, iobuf);
                if (pkt_len > Protocol.AesCtrT.block_size) { // if there's more to be decrypted after first block
                    const remaining_pkt_bytes = pkt_len - Protocol.AesCtrT.block_size;
                    var dec: [Protocol.MaxSSHPacket]u8 = undefined;
                    defer std.crypto.secureZero(u8, &dec);
                    inkeys.aesctr.encrypt(
                        iobuf[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes],
                        dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes],
                    ) catch return IoError.KeyLifetimeExceeded;

                    UNSAFE_TRACEDUMP(.Debug, "dec", .{}, dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]);
                    // copy decrypted back into writebuf
                    @memcpy(iobuf[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes], dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]);
                    UNSAFE_TRACEDUMP(.Debug, "writebuf", .{}, iobuf[0..pkt_len]);
                }

                // verify mac
                const rxmac = iobuf[frame.mac_offset.?..iobuf.len];
                var calcmac: [Protocol.mac_algo.key_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &calcmac);
                var m = Protocol.mac_algo.init(inkeys.mackey[0..Protocol.mac_algo.key_length]);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&m));
                const seq = std.mem.nativeTo(u32, inkeys.seq - 1, .big); // seq has already been incremented
                m.update(std.mem.asBytes(&seq));
                m.update(iobuf[0..pkt_len]); // plaintext
                m.final(&calcmac);

                UNSAFE_TRACEDUMP(.Debug, "rxmac", .{}, rxmac);
                UNSAFE_TRACEDUMP(.Debug, "mackey", .{}, inkeys.mackey[0..Protocol.mac_algo.key_length]);
                UNSAFE_TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
                UNSAFE_TRACEDUMP(.Debug, "macdata", .{}, iobuf[0..pkt_len]);
                UNSAFE_TRACEDUMP(.Debug, "calcmac", .{}, std.mem.asBytes(&calcmac));

                try verifyPacketMac(calcmac, rxmac);
                try inkeys.accountEncryptedPacket(pkt_len);

                // remove mac and return buffer containing just plaintext payload
                const decrypted_payload = iobuf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];
                const decompressed = try inkeys.compression.decompressPayload(
                    decrypted_payload,
                    self.iobuf_decompressed[0..self.limits.max_decompressed_payload_size],
                );
                return BufferReader.init(decompressed);
            }
        }

        fn advanceIoSession(self: *Self, inkeys: *Protocol.KeyDataUni) SshzError!void {
            switch (self.session.ioSessionState) {
                .Idle => {
                    TRACE(.Debug, "ioSessionState Idle", .{});
                    try self.session.advanceSession(self);
                },
                .Init => {
                    switch (role) {
                        .Client => self.session.setIoSessionState(.VersionWrite),
                        .Server => self.session.setIoSessionState(.VersionReadLine),
                    }
                },
                .VersionWrite => {
                    const sl = self.session.writeProtocolVersion(&self.iobuf_wr);
                    switch (role) {
                        .Client => try self.requestWrite(sl, .VersionReadLine),
                        .Server => try self.requestWrite(sl, .Idle),
                    }
                },
                .VersionReadLine => {
                    // read first char
                    self.requestRead(0, 1, .{ .VersionReadLineChar = self.iobuf_rd[0..1] });
                },
                .VersionReadLineChar => |buf| {
                    if (buf.len >= 1 and buf[buf.len - 1] == '\n') {
                        self.session.setIoSessionState(.{ .VersionReadLineCompletion = buf });
                        return;
                    }
                    if (buf.len >= Protocol.MaxIdentificationLineLen) return IoError.noEOLFound;
                    self.requestRead(buf.len, 1, .{ .VersionReadLineChar = self.iobuf_rd[0 .. buf.len + 1] });
                },
                .VersionReadLineCompletion => |buf| {
                    if (buf.len > self.limits.max_identification_bytes -| self.identification_bytes)
                        return IoError.ResourceLimitExceeded;
                    self.identification_bytes += buf.len;
                    if (!std.mem.startsWith(u8, buf, "SSH-")) {
                        if (comptime role == .Server) return IoError.UnexpectedResponse;
                        self.session.pre_identification_lines += 1;
                        if (self.session.pre_identification_lines > self.limits.max_identification_lines)
                            return IoError.ResourceLimitExceeded;
                        self.session.setIoSessionState(.VersionReadLine);
                        return;
                    }

                    const version = try inspectIdentificationLine(buf);
                    TRACE(.Debug, "RX: version '{s}'", .{version});
                    try self.session.setPeerProtocolVersion(version);
                    switch (role) {
                        .Client => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_S),
                        .Server => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_C),
                    }
                    self.session.kex_hasher.writeU32LenString(version);
                    switch (role) {
                        .Client => {
                            self.session.setIoSessionState(.Idle);
                            self.requestEvent(.{ .ServerIdentification = self.session.server_version.? }, .Idle);
                        },
                        .Server => self.session.setIoSessionState(.VersionWrite),
                    }
                },
                .WriteCompletePreserveState => return IoError.UnexpectedResponse,
                .GlobalRequestWriteComplete => return IoError.UnexpectedResponse,
                .ChannelWriteComplete => return IoError.UnexpectedResponse,
                .ChannelControlComplete => return IoError.UnexpectedResponse,
                .ReadPktHdr => {
                    _ = try self.session.dispatchDeferredChannelWrite(self);
                    if (self.session.inbound_encrypted) {
                        self.requestRead(0, Protocol.AesCtrT.block_size, .{ .ReadPktBody = self.iobuf_rd[0..Protocol.AesCtrT.block_size] });
                    } else {
                        self.requestRead(0, Protocol.sizeof_PktHdr, .{ .ReadPktBody = self.iobuf_rd[0..Protocol.sizeof_PktHdr] });
                    }
                },
                .ReadPktBody => |buf| {
                    if (inkeys.seq == std.math.maxInt(u32)) return IoError.KeyLifetimeExceeded;
                    if (self.session.inbound_encrypted) {
                        // https://datatracker.ietf.org/doc/html/rfc4253#section-6
                        // grab first encrypted block from writebuf
                        var firstblock_encbuf: [Protocol.AesCtrT.block_size]u8 = undefined;
                        defer std.crypto.secureZero(u8, &firstblock_encbuf);
                        @memcpy(&firstblock_encbuf, buf);

                        // decrypt directly into iobuf_rd
                        inkeys.aesctr.encrypt(
                            &firstblock_encbuf,
                            self.iobuf_rd[0..Protocol.AesCtrT.block_size],
                        ) catch return IoError.KeyLifetimeExceeded;
                        UNSAFE_TRACEDUMP(.Debug, "firstblock_dec(in payload)", .{}, self.iobuf_rd[0..Protocol.AesCtrT.block_size]);

                        const frame = try inspectPacketHeaderWithLimits(
                            buf,
                            true,
                            self.limits.max_packet_size,
                            self.limits.max_payload_size,
                        );
                        const pkt_len = frame.packet_len;

                        // calc number of remaining bytes + mac, read from network
                        var remaining_pkt_bytes: usize = 0;
                        if (pkt_len > Protocol.AesCtrT.block_size) {
                            remaining_pkt_bytes = pkt_len - Protocol.AesCtrT.block_size;
                        }
                        TRACE(.Debug, "About to read {d}\n", .{remaining_pkt_bytes + Protocol.mac_algo.key_length});
                        //
                        self.requestRead(buf.len, (remaining_pkt_bytes + Protocol.mac_algo.key_length), .{ .ReadPktCompletion = self.iobuf_rd[0 .. buf.len + remaining_pkt_bytes + Protocol.mac_algo.key_length] }); // on completion, how much we have

                        inkeys.seq += 1;
                    } else {
                        const frame = try inspectPacketHeaderWithLimits(
                            buf,
                            false,
                            self.limits.max_packet_size,
                            self.limits.max_payload_size,
                        );

                        self.requestRead(buf.len, frame.packet_len - buf.len, .{ .ReadPktCompletion = self.iobuf_rd[0..frame.packet_len] });
                        inkeys.seq += 1;
                    }
                },
                .ReadPktCompletion => |buf| {
                    UNSAFE_TRACEDUMP(.Debug, ".ReadPktCompletion", .{}, buf);
                    try self.session.handlePacket(buf, self);
                },
            }
        }

        fn canProcessIoSessionState(self: *Self) bool {
            return switch (self.session.ioSessionState) {
                // Idle needs both sides free — session will decide what to do
                .Idle => self.iostate_rd == .Idle and self.iostate_wr == .Idle,
                .Init => true,
                // Read-requiring states only need read side idle
                .VersionReadLine, .VersionReadLineChar => self.iostate_rd == .Idle,
                .ReadPktHdr, .ReadPktBody => self.iostate_rd == .Idle,
                // Write-requiring states need write side idle
                .VersionWrite => self.iostate_wr == .Idle,
                .WriteCompletePreserveState => false,
                .GlobalRequestWriteComplete => false,
                .ChannelWriteComplete => false,
                .ChannelControlComplete => false,
                // Processing states
                .VersionReadLineCompletion => true, // just sets next ioSessionState
                .ReadPktCompletion => self.iostate_wr == .Idle, // handlePacket may event/write
            };
        }

        pub fn advance(self: *Self) SshzError!void {
            if (self.terminated) return IoError.SessionTerminated;
            errdefer self.failClosed();
            if (role == .Client) {
                _ = try self.session.flushPendingWindowChange(self);
                // Receive credit may be queued while another packet owns the
                // write side, even though a packet-header read is still active.
                _ = try self.session.flushPendingChannelWindowAdjust(self);
            }
            const inkeys = switch (role) {
                .Client => &self.session.keydata.s2c,
                .Server => &self.session.keydata.c2s,
            };
            while (true) {
                self.updateLocalRekeyPending(null);
                _ = self.maybeStartLocalRekey();
                if (role == .Client) _ = try self.session.flushPendingKeepalive(self);
                if (!self.canProcessIoSessionState()) break;
                const prev_io_state = self.session.ioSessionState;
                const prev_rd = self.iostate_rd;
                const prev_wr = self.iostate_wr;
                try self.advanceIoSession(inkeys);
                // Break if no progress was made to prevent infinite loops
                const same_io = std.meta.eql(prev_io_state, self.session.ioSessionState);
                const same_rd = std.meta.eql(prev_rd, self.iostate_rd);
                const same_wr = std.meta.eql(prev_wr, self.iostate_wr);
                if (same_io and same_rd and same_wr) break;
            }
        }

        pub fn setPrivateKey(self: *Self, keydata_ascii: []const u8) SshzError!void {
            return switch (role) {
                .Client => try self.session.setPrivateKey(keydata_ascii),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn setPrivateKeyPassphrase(self: *Self, data: []const u8) SshzError!void {
            return switch (role) {
                .Client => try self.session.setPrivateKeyPassphrase(data),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn setAuthPassphrase(self: *Self, data: []const u8) SshzError!void {
            return switch (role) {
                .Client => try self.session.setAuthPassphrase(data),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn setTryNoneAuth(self: *Self, enabled: bool) SshzError!void {
            return switch (role) {
                .Client => self.session.setTryNoneAuth(enabled),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn isActive(self: *Self) bool {
            return self.session.isActive();
        }

        pub fn getChannelWriteBuffer(self: *Self, channel_id: u32) SshzError![]u8 {
            return self.session.getChannelWriteBuffer(channel_id);
        }

        pub fn channelWriteComplete(self: *Self, channel_id: u32, nbytes: usize) SshzError!void {
            if (self.iostate_wr != .Idle) return IoError.cannotAcceptWrite;
            self.updateLocalRekeyPending(null);
            if (self.local_rekey_pending or self.session.is_rekeying) {
                _ = try self.session.queueChannelWrite(channel_id, nbytes);
                _ = self.maybeStartLocalRekey();
                return;
            }
            if (self.iostate_rd != .Idle) {
                self.session.directChannelWrite(channel_id, nbytes, self) catch |err| {
                    self.latchKeyLifetimeError(err);
                    return err;
                };
            } else {
                try self.session.channelWriteComplete(channel_id, nbytes);
                try self.advance();
            }
        }

        /// Returns receive-window credit for an ordinary client channel.
        ///
        /// This is valid only after automatic channel read credit has been
        /// disabled and no more than the bytes delivered through borrowed
        /// `RxData` or `RxExtendedData` events may be credited.
        pub fn channelReadConsumed(self: *Self, channel_id: u32, count: usize) SshzError!void {
            return switch (role) {
                .Client => {
                    self.session.channelReadConsumed(channel_id, count, self) catch |err| {
                        self.latchKeyLifetimeError(err);
                        return err;
                    };
                    try self.advance();
                },
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn openSessionChannel(self: *Self) SshzError!u32 {
            try self.gateApplicationInitiation();
            return switch (role) {
                .Client => self.session.openSessionChannel(self) catch |err| {
                    self.latchKeyLifetimeError(err);
                    return err;
                },
                .Server => IoError.UnimplementedService,
            };
        }

        /// Returns the automatic session channel ID once it has been allocated.
        ///
        /// The ID remains available after channel close and `EndSession`.
        pub fn automaticSessionChannelId(self: *const Self) ?u32 {
            return switch (role) {
                .Client => self.session.automaticSessionChannelId(),
                .Server => null,
            };
        }

        /// Returns a session channel's terminal result when one is available.
        ///
        /// Signal strings are owned by the client. Returned slices remain valid
        /// until `clearChannelExitResult(channel_id)` or `deinit`.
        pub fn channelExitResult(self: *const Self, channel_id: u32) ?ChannelExitResult {
            return switch (role) {
                .Client => self.session.channelExitResult(channel_id),
                .Server => null,
            };
        }

        /// Releases a completed session channel result and its reserved slot.
        ///
        /// Returns false while the channel is still open or when no reservation
        /// exists. Applications must release completed results before opening
        /// more session channels once the configured channel capacity is used.
        pub fn clearChannelExitResult(self: *Self, channel_id: u32) bool {
            return switch (role) {
                .Client => self.session.clearChannelExitResult(channel_id),
                .Server => false,
            };
        }

        /// Controls whether authentication automatically opens a session channel.
        ///
        /// Disable this before connecting when the client only needs channels
        /// such as `direct-tcpip`. `.Connected` is then emitted immediately
        /// after authentication, with every configured channel slot available.
        pub fn setAutoSessionEnabled(self: *Self, enabled: bool) SshzError!void {
            return switch (role) {
                .Client => try self.session.setAutoSessionEnabled(enabled),
                .Server => IoError.UnimplementedService,
            };
        }

        /// Controls automatic receive-window replenishment for ordinary channels.
        ///
        /// Disable this before opening channels to return credit explicitly with
        /// `channelReadConsumed`. Agent channels retain automatic credit.
        pub fn setAutoChannelReadCreditEnabled(self: *Self, enabled: bool) SshzError!void {
            return switch (role) {
                .Client => try self.session.setAutoChannelReadCreditEnabled(enabled),
                .Server => IoError.UnimplementedService,
            };
        }

        /// Configures the automatically opened session to send an `exec`
        /// request. No PTY is requested unless `setAutoPty` is also called.
        pub fn setAutoExecCommand(self: *Self, command: []const u8) SshzError!void {
            return switch (role) {
                .Client => try self.session.setAutoExecCommand(command),
                .Server => IoError.UnimplementedService,
            };
        }

        /// Configures and explicitly requests a PTY for the automatic session.
        ///
        /// This may be called before or after `setAutoExecCommand`. Automatic
        /// shells request a PTY even when this setter is not called.
        pub fn setAutoPty(self: *Self, term: []const u8, cols: u32, rows: u32, width_px: u32, height_px: u32) SshzError!void {
            return switch (role) {
                .Client => try self.session.setAutoPty(term, cols, rows, width_px, height_px),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn openDirectTcpipChannel(
            self: *Self,
            host: []const u8,
            port: u32,
            originator_host: []const u8,
            originator_port: u32,
        ) SshzError!u32 {
            try self.gateApplicationInitiation();
            return switch (role) {
                .Client => self.session.openDirectTcpipChannel(
                    self,
                    host,
                    port,
                    originator_host,
                    originator_port,
                ) catch |err| {
                    self.latchKeyLifetimeError(err);
                    return err;
                },
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn openLocalForwardChannel(
            self: *Self,
            host: []const u8,
            port: u32,
            originator_host: []const u8,
            originator_port: u32,
        ) SshzError!u32 {
            return try self.openDirectTcpipChannel(host, port, originator_host, originator_port);
        }

        pub fn requestRemoteForward(self: *Self, bind_address: []const u8, bind_port: u32) SshzError!void {
            try self.gateApplicationInitiation();
            return switch (role) {
                .Client => self.session.requestRemoteForward(self, bind_address, bind_port) catch |err| {
                    self.latchKeyLifetimeError(err);
                    return err;
                },
                .Server => IoError.UnimplementedService,
            };
        }

        /// Explicitly queues `keepalive@openssh.com` with want_reply=true.
        ///
        /// Shares the one outstanding global-request slot with forwarding.
        /// Returns ResourceLimitExceeded if that slot or the previous keepalive
        /// result is occupied. Accepted requests may wait for output or rekey;
        /// no clock, timeout, retry, or automatic probing policy is installed.
        pub fn requestKeepalive(self: *Self) SshzError!KeepaliveToken {
            if (self.terminated) return IoError.SessionTerminated;
            return switch (role) {
                .Client => {
                    const token = try self.session.queueKeepalive();
                    try self.advance();
                    return token;
                },
                .Server => IoError.UnimplementedService,
            };
        }

        /// Returns an owned snapshot, retained until `clearKeepalive`.
        pub fn keepaliveStatus(self: *const Self, token: KeepaliveToken) SshzError!KeepaliveStatus {
            return switch (role) {
                .Client => self.session.keepaliveStatus(token),
                .Server => IoError.UnimplementedService,
            };
        }

        /// Confirms an application-owned transport flush, not peer receipt.
        ///
        /// Call only after HandedToTransport and after the underlying stream
        /// accepted all bytes through this request. A direct socket pump may
        /// call this after its final successful send/consumed pair. A buffering
        /// adapter must record that byte-stream boundary and wait for its own
        /// queue to flush through it. Start a reply deadline only at that point.
        pub fn markKeepaliveFlushed(self: *Self, token: KeepaliveToken) SshzError!void {
            return switch (role) {
                .Client => self.session.markKeepaliveFlushed(token),
                .Server => IoError.UnimplementedService,
            };
        }

        /// Abandons observation. A framed request still drains and reserves the
        /// global-request slot until its reply arrives or the session ends.
        /// For a late-reply grace period, leave the request Pending instead.
        pub fn cancelKeepalive(self: *Self, token: KeepaliveToken) SshzError!void {
            return switch (role) {
                .Client => self.session.cancelKeepalive(token),
                .Server => IoError.UnimplementedService,
            };
        }

        /// Releases a terminal snapshot. Pending returns NotReady. Clearing a
        /// cancelled result never releases an outstanding on-wire reply slot.
        pub fn clearKeepalive(self: *Self, token: KeepaliveToken) SshzError!void {
            return switch (role) {
                .Client => self.session.clearKeepalive(token),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn cancelRemoteForward(self: *Self, bind_address: []const u8, bind_port: u32) SshzError!void {
            try self.gateApplicationInitiation();
            return switch (role) {
                .Client => self.session.cancelRemoteForward(self, bind_address, bind_port) catch |err| {
                    self.latchKeyLifetimeError(err);
                    return err;
                },
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn openForwardedTcpipChannel(
            self: *Self,
            connected_host: []const u8,
            connected_port: u32,
            originator_host: []const u8,
            originator_port: u32,
        ) SshzError!u32 {
            try self.gateApplicationInitiation();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => self.session.openForwardedTcpipChannel(
                    self,
                    connected_host,
                    connected_port,
                    originator_host,
                    originator_port,
                ) catch |err| {
                    self.latchKeyLifetimeError(err);
                    return err;
                },
            };
        }

        fn clearPendingChannelOpenRequest(self: *Self, channel_id: u32) SshzError!void {
            switch (self.iostate_wr) {
                .Idle => return,
                .Active => |iotype| switch (iotype.action) {
                    .Eventing => |eventCode| switch (eventCode) {
                        .ChannelOpenRequest => |request| {
                            if (request.channel != channel_id) return IoError.badClearEvent;
                            self.session.setIoSessionState(iotype.next_state);
                            self.iostate_wr = .Idle;
                            self.scrubReceiveBuffers();
                            return;
                        },
                        else => return IoError.badClearEvent,
                    },
                    else => return IoError.cannotAcceptWrite,
                },
            }
        }

        fn clearPendingHostKeyEvent(self: *Self) SshzError!void {
            return switch (role) {
                .Server => IoError.UnimplementedService,
                .Client => switch (self.iostate_wr) {
                    .Idle => IoError.badClearEvent,
                    .Active => |iotype| switch (iotype.action) {
                        .Eventing => |eventCode| switch (eventCode) {
                            .CheckHostKey => {
                                self.session.setIoSessionState(iotype.next_state);
                                self.iostate_wr = .Idle;
                                self.scrubReceiveBuffers();
                            },
                            else => return IoError.badClearEvent,
                        },
                        else => IoError.cannotAcceptWrite,
                    },
                },
            };
        }

        /// Accepts the signature-verified host key from the pending CheckHostKey event.
        pub fn acceptHostKey(self: *Self) SshzError!void {
            try self.clearPendingHostKeyEvent();
            return switch (role) {
                .Client => {
                    try self.session.acceptHostKey();
                    try self.advance();
                },
                .Server => IoError.UnimplementedService,
            };
        }

        /// Rejects the pending host key and ends the client session before authentication.
        pub fn rejectHostKey(self: *Self) SshzError!void {
            try self.clearPendingHostKeyEvent();
            return switch (role) {
                .Client => {
                    try self.session.rejectHostKey(self);
                    try self.advance();
                },
                .Server => IoError.UnimplementedService,
            };
        }

        fn clearPendingTcpipForwardEvent(self: *Self) SshzError!void {
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    switch (self.iostate_wr) {
                        .Idle => return IoError.badClearEvent,
                        .Active => |iotype| switch (iotype.action) {
                            .Eventing => |eventCode| switch (eventCode) {
                                .TcpipForward => {
                                    self.session.setIoSessionState(iotype.next_state);
                                    self.iostate_wr = .Idle;
                                    self.scrubReceiveBuffers();
                                },
                                else => return IoError.badClearEvent,
                            },
                            else => return IoError.cannotAcceptWrite,
                        },
                    }
                },
            };
        }

        fn clearPendingCancelTcpipForwardEvent(self: *Self) SshzError!void {
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    switch (self.iostate_wr) {
                        .Idle => return IoError.badClearEvent,
                        .Active => |iotype| switch (iotype.action) {
                            .Eventing => |eventCode| switch (eventCode) {
                                .CancelTcpipForward => {
                                    self.session.setIoSessionState(iotype.next_state);
                                    self.iostate_wr = .Idle;
                                    self.scrubReceiveBuffers();
                                },
                                else => return IoError.badClearEvent,
                            },
                            else => return IoError.cannotAcceptWrite,
                        },
                    }
                },
            };
        }

        pub fn acceptTcpipForward(self: *Self, bound_port: u32) SshzError!void {
            try self.clearPendingTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.acceptTcpipForward(self, bound_port);
                    try self.advance();
                },
            };
        }

        pub fn rejectTcpipForward(self: *Self) SshzError!void {
            try self.clearPendingTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.rejectTcpipForward(self);
                    try self.advance();
                },
            };
        }

        pub fn acceptCancelTcpipForward(self: *Self) SshzError!void {
            try self.clearPendingCancelTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.acceptCancelTcpipForward(self);
                    try self.advance();
                },
            };
        }

        pub fn rejectCancelTcpipForward(self: *Self) SshzError!void {
            try self.clearPendingCancelTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.rejectCancelTcpipForward(self);
                    try self.advance();
                },
            };
        }

        pub fn acceptChannelOpen(self: *Self, channel_id: u32) SshzError!void {
            try self.clearPendingChannelOpenRequest(channel_id);
            try self.session.acceptChannelOpen(channel_id);
            try self.advance();
        }

        pub fn rejectChannelOpen(self: *Self, channel_id: u32, reason_code: u32, description: []const u8) SshzError!void {
            try self.clearPendingChannelOpenRequest(channel_id);
            try self.session.rejectChannelOpen(channel_id, reason_code, description);
            try self.advance();
        }

        pub fn sendChannelEof(self: *Self, channel_id: u32) SshzError!void {
            self.updateLocalRekeyPending(null);
            _ = self.maybeStartLocalRekey();
            self.session.sendChannelEof(channel_id, self) catch |err| {
                self.latchKeyLifetimeError(err);
                return err;
            };
            try self.advance();
        }

        /// Reports whether a requested channel EOF and all preceding data have
        /// been written to the transport.
        pub fn channelEofFlushed(self: *Self, channel_id: u32) SshzError!bool {
            return switch (role) {
                .Client => self.session.channelEofFlushed(channel_id),
                .Server => self.session.channelEofFlushed(channel_id),
            };
        }

        pub fn sendChannelClose(self: *Self, channel_id: u32) SshzError!void {
            self.updateLocalRekeyPending(null);
            _ = self.maybeStartLocalRekey();
            self.session.sendChannelClose(channel_id, self) catch |err| {
                self.latchKeyLifetimeError(err);
                return err;
            };
            try self.advance();
        }

        pub fn enableAgentForwarding(self: *Self) SshzError!void {
            switch (role) {
                .Client => return try self.session.enableAgentForwarding(),
                .Server => return IoError.UnimplementedService,
            }
        }

        pub fn openAgentChannel(self: *Self) SshzError!u32 {
            try self.gateApplicationInitiation();
            switch (role) {
                .Client => return IoError.UnimplementedService,
                .Server => {
                    self.iostate_rd = .Idle;
                    self.iostate_wr = .Idle;
                    const channel_id = try self.session.openAgentChannel();
                    try self.advance();
                    return channel_id;
                },
            }
        }
    };
}

fn feedClientIdentificationBytes(client: *SshzClient, bytes: []const u8) !void {
    for (bytes) |byte| {
        const evt = try client.getNextEvent();
        const can_consume = switch (evt) {
            .ReadyToConsume => |n| n,
            .ReadyToConsumeAndProduce => |sizes| sizes.consume,
            else => return error.TestUnexpectedResult,
        };
        try std.testing.expect(can_consume > 0);
        try client.write(&.{byte});
    }
}

fn startClientIdentificationRead(client: *SshzClient) !void {
    const initial = try client.getNextEvent();
    switch (initial) {
        .ReadyToProduce => {},
        else => return error.TestUnexpectedResult,
    }
    const client_identification = try client.peek(Protocol.MaxIdentificationLineLen);
    try client.consumed(client_identification.len);
}

test "packet MAC verification accepts a matching MAC" {
    const mac = [1]u8{0xa5} ** Protocol.mac_algo.key_length;
    try verifyPacketMac(mac, &mac);
}

test "packet MAC verification rejects a different or incorrectly sized MAC" {
    const mac = [1]u8{0xa5} ** Protocol.mac_algo.key_length;
    var different = mac;
    different[different.len - 1] ^= 1;

    try std.testing.expectError(IoError.InvalidMac, verifyPacketMac(mac, &different));
    try std.testing.expectError(IoError.InvalidMac, verifyPacketMac(mac, different[0 .. different.len - 1]));
}

test "EndSessionReason tagged union" {
    const reason_disconnect: EndSessionReason = .Disconnect;
    const reason_auth: EndSessionReason = .{ .AuthFailure = AuthFailureInfo.parse(
        .Password,
        "keyboard-interactive",
        true,
        2,
    ) };
    const reason_server: EndSessionReason = .{ .ServerDisconnect = .{
        .code = 11,
        .description = "test disconnect",
    } };

    switch (reason_disconnect) {
        .Disconnect => {},
        else => return error.TestUnexpectedResult,
    }

    switch (reason_auth) {
        .AuthFailure => |failure| {
            try std.testing.expectEqual(AuthMethod.Password, failure.attempted_method);
            try std.testing.expectEqualSlices(
                AuthMethod,
                &.{.KeyboardInteractive},
                failure.supportedMethods(),
            );
            try std.testing.expect(failure.partial_success);
            try std.testing.expectEqual(@as(u8, 2), failure.auth_stage);
        },
        else => return error.TestUnexpectedResult,
    }

    switch (reason_server) {
        .ServerDisconnect => |r| {
            try std.testing.expectEqual(@as(u32, 11), r.code);
            try std.testing.expectEqualStrings("test disconnect", r.description);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "AuthFailureInfo public API is value-owned for apk2" {
    var method_names = "publickey,gssapi-with-mic,password".*;
    const failure = AuthFailureInfo.parse(.None, &method_names, true, 3);
    @memset(&method_names, 'x');

    try std.testing.expectEqual(AuthMethod.None, failure.attempted_method);
    try std.testing.expectEqualSlices(
        AuthMethod,
        &.{ .PublicKey, .Password },
        failure.supportedMethods(),
    );
    try std.testing.expectEqual(@as(u8, 2), failure.supported_methods_len);
    try std.testing.expectEqualStrings("gssapi-with-mic", failure.unsupportedMethodNames());
    try std.testing.expectEqual(@as(u8, "gssapi-with-mic".len), failure.unsupported_methods_len);
    try std.testing.expectEqual(@as(usize, 128), failure.unsupported_methods.len);
    try std.testing.expect(failure.partial_success);
    try std.testing.expectEqual(@as(u8, 3), failure.auth_stage);

    var long_unsupported: [AuthFailureInfo.MaxUnsupportedMethodsLen + 16]u8 = undefined;
    @memset(&long_unsupported, 'u');
    const bounded = AuthFailureInfo.parse(.Password, &long_unsupported, false, 1);
    try std.testing.expectEqual(
        @as(usize, AuthFailureInfo.MaxUnsupportedMethodsLen),
        bounded.unsupportedMethodNames().len,
    );
}

test "client retains exact server identification after RFC preamble" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();

    const initial = try client.getNextEvent();
    switch (initial) {
        .ReadyToProduce => {},
        else => return error.TestUnexpectedResult,
    }
    const client_identification = try client.peek(Protocol.MaxIdentificationLineLen);
    try std.testing.expectEqualStrings(Protocol.version ++ "\r\n", client_identification);
    try client.consumed(client_identification.len);

    try feedClientIdentificationBytes(&client, "NOTICE exact spaces  \r\n");
    try feedClientIdentificationBytes(&client, "SSH-2.0-test_server exact café  \r\n");

    const evt = try client.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ServerIdentification => |identification| {
                try std.testing.expectEqualStrings("SSH-2.0-test_server exact café  ", identification);
                try std.testing.expectEqualStrings(identification, client.session.server_version.?);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), client.session.pre_identification_lines);
}

test "client accepts 255 byte pre-identification and identification lines" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    try startClientIdentificationRead(&client);

    var preamble: [Protocol.MaxIdentificationLineLen]u8 = undefined;
    @memset(&preamble, 'p');
    preamble[preamble.len - 2] = '\r';
    preamble[preamble.len - 1] = '\n';
    try feedClientIdentificationBytes(&client, &preamble);

    var identification: [Protocol.MaxIdentificationLineLen]u8 = undefined;
    @memset(&identification, 's');
    const prefix = "SSH-2.0-";
    @memcpy(identification[0..prefix.len], prefix);
    identification[identification.len - 2] = '\r';
    identification[identification.len - 1] = '\n';
    try feedClientIdentificationBytes(&client, &identification);

    const evt = try client.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ServerIdentification => |server_identification| {
                try std.testing.expectEqual(
                    Protocol.MaxIdentificationLineLen - 2,
                    server_identification.len,
                );
                try std.testing.expectEqualStrings(
                    identification[0 .. identification.len - 2],
                    server_identification,
                );
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), client.session.pre_identification_lines);
}

test "client accepts and hashes exact 255 byte LF-only SSH 1.99 identification" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    try startClientIdentificationRead(&client);

    var identification: [Protocol.MaxIdentificationLineLen]u8 = undefined;
    @memset(&identification, 's');
    const prefix = "SSH-1.99-";
    @memcpy(identification[0..prefix.len], prefix);
    identification[identification.len - 1] = '\n';
    try feedClientIdentificationBytes(&client, &identification);

    const exact = identification[0 .. identification.len - 1];
    const evt = try client.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ServerIdentification => |server_identification| {
                try std.testing.expectEqualStrings(exact, server_identification);
                try std.testing.expectEqualStrings(exact, client.session.server_version.?);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    var expected_hasher = Hasher(Protocol.hash_algo).init();
    expected_hasher.writeU32LenString(Protocol.version);
    expected_hasher.writeU32LenString(exact);
    var expected: [Protocol.hash_algo.digest_length]u8 = undefined;
    expected_hasher.final(&expected, null);
    var actual: [Protocol.hash_algo.digest_length]u8 = undefined;
    client.session.kex_hasher.final(&actual, null);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "client rejects identification line whose CRLF would exceed 255 bytes" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    try startClientIdentificationRead(&client);

    var overlong: [Protocol.MaxIdentificationLineLen + 1]u8 = undefined;
    @memset(&overlong, 'x');
    overlong[overlong.len - 2] = '\r';
    overlong[overlong.len - 1] = '\n';
    try feedClientIdentificationBytes(&client, overlong[0 .. Protocol.MaxIdentificationLineLen - 1]);
    try std.testing.expectError(
        IoError.noEOLFound,
        client.write(overlong[Protocol.MaxIdentificationLineLen - 1 .. Protocol.MaxIdentificationLineLen]),
    );
}

test "client rejects unterminated 255 byte identification line" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    try startClientIdentificationRead(&client);

    var unterminated: [Protocol.MaxIdentificationLineLen]u8 = undefined;
    @memset(&unterminated, 'x');
    try feedClientIdentificationBytes(&client, unterminated[0 .. unterminated.len - 1]);
    try std.testing.expectError(
        IoError.noEOLFound,
        client.write(unterminated[unterminated.len - 1 ..]),
    );
}

test "client rejects malformed SSH identification grammar and bytes" {
    const malformed = [_][]const u8{
        "SSH-2.0-\r\n",
        "SSH-2.0- comment-without-software\r\n",
        "SSH-two.server\r\n",
        "SSH-2.0-server\x01comment\r\n",
        "SSH-2.0-server\x7fcomment\r\n",
        "SSH-2.0-server\x80comment\r\n",
    };

    for (malformed) |line| {
        var prng = std.Random.DefaultPrng.init(42);
        var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
        defer client.deinit();
        try startClientIdentificationRead(&client);
        try std.testing.expectError(
            IoError.UnexpectedResponse,
            feedClientIdentificationBytes(&client, line),
        );
    }
}

test "client bounds pre-identification lines" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();

    _ = try client.getNextEvent();
    const client_identification = try client.peek(Protocol.MaxIdentificationLineLen);
    try client.consumed(client_identification.len);
    client.session.pre_identification_lines = Protocol.MaxPreIdentificationLines;

    const line = "one-too-many\r\n";
    try feedClientIdentificationBytes(&client, line[0 .. line.len - 1]);
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.write(line[line.len - 1 ..]));
    try std.testing.expectError(IoError.SessionTerminated, client.getNextEvent());
}

test "resource limits validate defaults capacities and invalid relationships" {
    try (ResourceLimits{}).validate();

    var limits = ResourceLimits{};
    limits.max_packet_size = ResourceCapacities.packet_size + 1;
    try std.testing.expectError(error.PacketLimitExceedsCapacity, limits.validate());

    limits = .{};
    limits.max_payload_size = ResourceCapacities.payload_size + 1;
    try std.testing.expectError(error.PayloadLimitExceedsCapacity, limits.validate());

    if (ResourceCapacities.channels < std.math.maxInt(u8)) {
        limits = .{};
        limits.max_channels = ResourceCapacities.channels + 1;
        try std.testing.expectError(error.ChannelLimitExceedsCapacity, limits.validate());
    }

    limits = .{};
    limits.initial_channel_window = 2;
    limits.max_channel_window = 1;
    try std.testing.expectError(error.InvalidChannelWindowLimits, limits.validate());

    limits = .{};
    limits.max_peer_packet_size = ResourceCapacities.channel_packet_size + 1;
    try std.testing.expectError(error.InvalidPeerPacketLimit, limits.validate());

    limits = .{};
    limits.max_channel_buffered_data = ResourceCapacities.channel_buffered_data + 1;
    try std.testing.expectError(error.BufferedDataLimitExceedsCapacity, limits.validate());

    limits = .{};
    limits.max_pending_buffered_data = ResourceCapacities.pending_buffered_data + 1;
    try std.testing.expectError(error.InvalidPendingDataLimit, limits.validate());

    limits = .{};
    limits.max_identification_lines = ResourceCapacities.identification_lines + 1;
    try std.testing.expectError(error.IdentificationLimitExceedsCapacity, limits.validate());

    limits = .{};
    limits.max_pre_auth_packets = 0;
    try std.testing.expectError(error.InvalidPreAuthLimit, limits.validate());

    limits = .{};
    limits.max_server_auth_attempts = 0;
    try std.testing.expectError(error.InvalidAuthAttemptLimit, limits.validate());

    limits = .{};
    limits.max_key_exchanges = 0;
    try std.testing.expectError(error.InvalidKeyExchangeLimit, limits.validate());
    limits = .{};
    limits.min_packets_between_rekeys = ResourceCapacities.rekey_spacing_packets + 1;
    try std.testing.expectError(error.InvalidKeyExchangeLimit, limits.validate());

    limits = .{};
    limits.key_lifetime.rekey_after_encrypted_bytes = 0;
    try std.testing.expectError(error.InvalidKeyLifetimeLimit, limits.validate());
    limits = .{};
    limits.key_lifetime.rekey_after_encrypted_bytes =
        ResourceCapacities.encrypted_bytes_per_key;
    try std.testing.expectError(error.InvalidKeyLifetimeLimit, limits.validate());
    limits = .{};
    limits.key_lifetime.rekey_after_encrypted_packets =
        ResourceCapacities.packets_per_sequence;
    try std.testing.expectError(error.InvalidKeyLifetimeLimit, limits.validate());
    limits = .{ .key_lifetime = .{ .rekey_after_monotonic_ticks = 0 } };
    try std.testing.expectError(error.InvalidKeyLifetimeLimit, limits.validate());

    limits = .{};
    limits.max_outstanding_global_requests = ResourceCapacities.outstanding_global_requests + 1;
    try std.testing.expectError(error.GlobalRequestLimitExceedsCapacity, limits.validate());

    limits = .{};
    limits.max_decompressed_payload_size = ResourceCapacities.decompressed_payload_size + 1;
    try std.testing.expectError(error.DecompressionLimitExceedsCapacity, limits.validate());

    limits = .{ .deadlines = .{ .idle = 0 } };
    try std.testing.expectError(error.InvalidDeadlineLimit, limits.validate());
}

test "runtime packet limit enforces below at and above wire size" {
    const limits = ResourceLimits{
        .max_packet_size = 128,
        .max_payload_size = 87,
        .initial_channel_window = 32,
        .channel_packet_size = 32,
        .max_peer_packet_size = 32,
        .max_channel_buffered_data = 32,
        .max_pending_buffered_data = 128,
        .max_decompressed_payload_size = 87,
    };
    var header: [Protocol.sizeof_PktHdr]u8 = undefined;

    std.mem.writeInt(u32, header[0..4], 122, .big);
    header[4] = 34;
    _ = try inspectPacketHeaderWithLimits(&header, false, limits.max_packet_size, limits.max_payload_size);

    std.mem.writeInt(u32, header[0..4], 124, .big);
    header[4] = 36;
    _ = try inspectPacketHeaderWithLimits(&header, false, limits.max_packet_size, limits.max_payload_size);

    std.mem.writeInt(u32, header[0..4], 125, .big);
    header[4] = 37;
    try std.testing.expectError(
        error.InvalidPacketSize,
        inspectPacketHeaderWithLimits(&header, false, limits.max_packet_size, limits.max_payload_size),
    );

    std.mem.writeInt(u32, header[0..4], 124, .big);
    header[4] = 36;
    _ = try inspectPacketHeaderWithLimits(&header, false, limits.max_packet_size, limits.max_payload_size);
    header[4] = 35;
    try std.testing.expectError(
        error.InvalidPacketSize,
        inspectPacketHeaderWithLimits(&header, false, limits.max_packet_size, limits.max_payload_size),
    );
}

test "identification byte limit accepts exact boundary then terminates" {
    const limits = ResourceLimits{ .max_identification_bytes = 4 };
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer client.deinit();
    try startClientIdentificationRead(&client);

    try feedClientIdentificationBytes(&client, "x\n");
    try feedClientIdentificationBytes(&client, "y\n");
    try std.testing.expectError(
        IoError.ResourceLimitExceeded,
        feedClientIdentificationBytes(&client, "z\n"),
    );
    try std.testing.expectError(IoError.SessionTerminated, client.getNextEvent());
}

test "pre-auth packet work and rekey limits fail closed at boundaries" {
    var limits = ResourceLimits{
        .max_pre_auth_packets = 2,
        .max_pre_auth_work = 16,
        .max_key_exchanges = 2,
        .min_packets_between_rekeys = 1,
    };
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer client.deinit();

    try client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE));
    try client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE));
    try std.testing.expectError(
        IoError.TooManyPreAuthPackets,
        client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE)),
    );
    try std.testing.expectError(IoError.SessionTerminated, client.getNextEvent());

    limits.max_pre_auth_packets = 20;
    limits.max_pre_auth_work = 9;
    var work_client = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer work_client.deinit();
    try work_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
    try work_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE));
    try std.testing.expectError(
        IoError.TooMuchPreAuthWork,
        work_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE)),
    );

    limits.max_pre_auth_work = 100;
    limits.min_packets_between_rekeys = 1;
    var frequency_client = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer frequency_client.deinit();
    try frequency_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
    try std.testing.expectError(
        IoError.RekeyTooFrequent,
        frequency_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT)),
    );

    limits.min_packets_between_rekeys = 0;
    var count_client = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer count_client.deinit();
    try count_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
    try count_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
    try std.testing.expectError(
        IoError.TooManyKeyExchanges,
        count_client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT)),
    );
}

test "server authentication attempt limit is independent of client attempts" {
    const privkey = @import("privkey.zig");
    const limits = ResourceLimits{ .max_server_auth_attempts = 2 };
    var prng = std.Random.DefaultPrng.init(42);
    var server = try SshzServer.initWithLimits(
        prng.random(),
        privkey.testkey_valid,
        std.testing.allocator,
        limits,
    );
    defer server.deinit();

    try server.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
    try server.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
    try std.testing.expectError(
        IoError.TooManyAuthAttempts,
        server.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST)),
    );

    var client = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer client.deinit();
    try client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
    try client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
    try client.accountInboundMessage(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
}

fn installAutomaticRekeyTestKeys(keydata: *Protocol.KeyDataBi) !void {
    const hash: [Protocol.hash_algo.digest_length]u8 = .{0x31} ** Protocol.hash_algo.digest_length;
    const secret: [Protocol.kex_algo.shared_length]u8 = .{0x42} ** Protocol.kex_algo.shared_length;
    const session_id: [Protocol.hash_algo.digest_length]u8 = .{0x53} ** Protocol.hash_algo.digest_length;
    try keydata.genKeys(hash, secret, session_id);
    try keydata.c2s.activateEpoch(0, null);
    try keydata.s2c.activateEpoch(0, null);
}

test "automatic rekey thresholds are deterministic below at and above" {
    const limits = ResourceLimits{ .key_lifetime = .{
        .rekey_after_encrypted_bytes = 100,
        .rekey_after_encrypted_packets = 10,
        .rekey_after_monotonic_ticks = 20,
    } };
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.initWithLimits(
        prng.random(),
        "test",
        std.testing.allocator,
        limits,
    );
    defer client.deinit();

    const keys = &client.session.keydata.c2s;
    keys.epoch = 1;
    keys.activated_at_monotonic_tick = 100;

    keys.encrypted_bytes = 99;
    try std.testing.expect(!client.keyUsageDue(keys, 119));
    keys.encrypted_bytes = 100;
    try std.testing.expect(client.keyUsageDue(keys, 119));
    keys.encrypted_bytes = 101;
    try std.testing.expect(client.keyUsageDue(keys, 119));

    keys.encrypted_bytes = 0;
    keys.encrypted_packets = 9;
    try std.testing.expect(!client.keyUsageDue(keys, 119));
    keys.encrypted_packets = 10;
    try std.testing.expect(client.keyUsageDue(keys, 119));
    keys.encrypted_packets = 11;
    try std.testing.expect(client.keyUsageDue(keys, 119));

    keys.encrypted_packets = 0;
    try std.testing.expect(!client.keyUsageDue(keys, 119));
    try std.testing.expect(client.keyUsageDue(keys, 120));
    try std.testing.expect(client.keyUsageDue(keys, 121));
}

test "client and server initiate automatic rekey and expose safe status" {
    const privkey = @import("privkey.zig");
    const limits = ResourceLimits{ .key_lifetime = .{
        .rekey_after_encrypted_bytes = 1000,
        .rekey_after_encrypted_packets = 1,
    } };
    var cprng = std.Random.DefaultPrng.init(43);
    var client = try SshzClient.initWithLimits(
        cprng.random(),
        "test",
        std.testing.allocator,
        limits,
    );
    defer client.deinit();
    try client.session.setPeerProtocolVersion("SSH-2.0-test_server");
    try installAutomaticRekeyTestKeys(&client.session.keydata);
    client.session.encrypted = true;
    client.session.inbound_encrypted = true;
    client.session.keydata.c2s.encrypted_packets = 1;
    client.session.setSessionState(.ChannelActive);
    client.session.setIoSessionState(.ReadPktHdr);

    const client_event = try client.getNextEvent();
    try std.testing.expect(client_event == .ReadyToProduce);
    try std.testing.expect(client.session.is_rekeying);
    try std.testing.expectEqual(ClientSessionState.KexInitRead, client.session.sessionState);
    const client_status = client.keyLifetimeStatus();
    try std.testing.expect(client_status.rekey_in_progress);
    try std.testing.expectEqual(@as(u64, 1), client_status.outbound.epoch);
    try std.testing.expect(client_status.outbound.encrypted_bytes > 0);
    try std.testing.expectEqual(@as(u64, 2), client_status.outbound.encrypted_packets);

    var sprng = std.Random.DefaultPrng.init(44);
    var server = try SshzServer.initWithLimits(
        sprng.random(),
        privkey.testkey_valid,
        std.testing.allocator,
        limits,
    );
    defer server.deinit();
    try server.session.setPeerProtocolVersion("SSH-2.0-test_client");
    try installAutomaticRekeyTestKeys(&server.session.keydata);
    server.session.encrypted = true;
    server.session.inbound_encrypted = true;
    server.session.keydata.s2c.encrypted_packets = 1;
    server.session.setSessionState(.ChannelActive);
    server.session.setIoSessionState(.ReadPktHdr);

    const server_event = try server.getNextEvent();
    try std.testing.expect(server_event == .ReadyToProduce);
    try std.testing.expect(server.session.is_rekeying);
    try std.testing.expectEqual(ServerSessionState.KexInitRead, server.session.sessionState);
    try std.testing.expect(server.session.pending_server_kexinit != null);
    const server_status = server.keyLifetimeStatus();
    try std.testing.expect(server_status.rekey_in_progress);
    try std.testing.expectEqual(@as(u64, 2), server_status.outbound.encrypted_packets);
}

test "automatic rekey gates channel data until a committed read finishes" {
    const limits = ResourceLimits{ .key_lifetime = .{
        .rekey_after_encrypted_bytes = 1000,
        .rekey_after_encrypted_packets = 1,
    } };
    var prng = std.Random.DefaultPrng.init(45);
    var client = try SshzClient.initWithLimits(
        prng.random(),
        "test",
        std.testing.allocator,
        limits,
    );
    defer client.deinit();
    try client.session.setPeerProtocolVersion("SSH-2.0-test_server");
    try installAutomaticRekeyTestKeys(&client.session.keydata);
    client.session.encrypted = true;
    client.session.inbound_encrypted = true;
    client.session.keydata.c2s.encrypted_packets = 1;
    client.session.setSessionState(.ChannelActive);
    client.session.setIoSessionState(.ReadPktHdr);
    const chan = client.session.channel_table.allocChannel(7, 1000, 1000).?;
    chan.state = .DataRx;
    @memcpy(chan.write_buf[0..4], "data");
    client.requestRead(0, 1, .ReadPktHdr);

    try client.channelWriteComplete(chan.local_id, 4);
    try std.testing.expectEqual(@as(usize, 4), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(usize, 0), chan.tx_in_flight_len);
    try std.testing.expect(!client.session.is_rekeying);

    client.iostate_rd = .Idle;
    const event = try client.getNextEvent();
    try std.testing.expect(event == .ReadyToProduce);
    try std.testing.expect(client.session.is_rekeying);
    try std.testing.expectEqual(@as(usize, 4), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(usize, 0), chan.tx_in_flight_len);
}

test "caller monotonic time initiates rekey without changing timeout meaning" {
    const rekey_limits = ResourceLimits{ .key_lifetime = .{
        .rekey_after_monotonic_ticks = 10,
    } };
    var prng = std.Random.DefaultPrng.init(46);
    var client = try SshzClient.initWithLimits(
        prng.random(),
        "test",
        std.testing.allocator,
        rekey_limits,
    );
    defer client.deinit();
    try client.session.setPeerProtocolVersion("SSH-2.0-test_server");
    try installAutomaticRekeyTestKeys(&client.session.keydata);
    client.session.encrypted = true;
    client.session.inbound_encrypted = true;
    client.session.setSessionState(.ChannelActive);
    client.session.setIoSessionState(.ReadPktHdr);
    try client.initializeDeadlines(100);
    try std.testing.expect((try client.tick(109)) == null);
    try std.testing.expect(!client.session.is_rekeying);
    try std.testing.expect((try client.tick(110)) == null);
    try std.testing.expect(client.session.is_rekeying);
    try std.testing.expect(client.timeoutOutcome() == null);

    const timeout_limits = ResourceLimits{
        .deadlines = .{ .idle = 10 },
        .key_lifetime = .{ .rekey_after_monotonic_ticks = 10 },
    };
    var timed_out = try SshzClient.initWithLimits(
        prng.random(),
        "test",
        std.testing.allocator,
        timeout_limits,
    );
    defer timed_out.deinit();
    try installAutomaticRekeyTestKeys(&timed_out.session.keydata);
    timed_out.session.encrypted = true;
    timed_out.session.inbound_encrypted = true;
    timed_out.session.setSessionState(.ChannelActive);
    timed_out.session.setIoSessionState(.ReadPktHdr);
    try timed_out.initializeDeadlines(200);
    try std.testing.expectEqual(TimeoutOutcome.Idle, (try timed_out.tick(210)).?);
    try std.testing.expect(!timed_out.session.is_rekeying);
    try std.testing.expectError(IoError.SessionTerminated, timed_out.getNextEvent());
}

test "inbound sequence hard bound terminates before wrap" {
    var prng = std.Random.DefaultPrng.init(47);
    var client = try SshzClient.init(prng.random(), "test", std.testing.allocator);
    defer client.deinit();
    client.session.keydata.s2c.seq = std.math.maxInt(u32);
    client.session.setIoSessionState(.{ .ReadPktBody = client.iobuf_rd[0..Protocol.sizeof_PktHdr] });
    client.iostate_rd = .Idle;
    client.iostate_wr = .Idle;

    try std.testing.expectError(IoError.KeyLifetimeExceeded, client.advance());
    try std.testing.expectError(IoError.SessionTerminated, client.getNextEvent());
}

test "direct application write latches key hard-bound failure" {
    var prng = std.Random.DefaultPrng.init(48);
    var client = try SshzClient.init(prng.random(), "test", std.testing.allocator);
    defer client.deinit();
    try installAutomaticRekeyTestKeys(&client.session.keydata);
    client.session.encrypted = true;
    client.session.inbound_encrypted = true;
    client.session.keydata.c2s.seq = std.math.maxInt(u32);
    client.session.setSessionState(.ChannelActive);
    client.session.setIoSessionState(.ReadPktHdr);
    const chan = client.session.channel_table.allocChannel(7, 1000, 1000).?;
    chan.state = .DataRx;
    @memcpy(chan.write_buf[0..4], "data");
    client.requestRead(0, 1, .ReadPktHdr);

    try std.testing.expectError(
        IoError.KeyLifetimeExceeded,
        client.channelWriteComplete(chan.local_id, 4),
    );
    try std.testing.expectError(IoError.SessionTerminated, client.getNextEvent());
}

test "caller-driven deadlines use monotonic fake time and typed outcomes" {
    const limits = ResourceLimits{ .deadlines = .{
        .handshake = 10,
        .authentication = 20,
        .idle = 30,
        .total_session = 40,
    } };
    var prng = std.Random.DefaultPrng.init(42);

    var handshake = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer handshake.deinit();
    try std.testing.expectError(error.DeadlinesNotInitialized, handshake.checkDeadlines(0));
    try handshake.initializeDeadlines(100);
    try std.testing.expect((try handshake.tick(109)) == null);
    try std.testing.expectEqual(TimeoutOutcome.Handshake, (try handshake.tick(110)).?);
    try std.testing.expectEqual(TimeoutOutcome.Handshake, handshake.timeoutOutcome().?);

    var auth = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer auth.deinit();
    auth.session.setSessionState(.AuthServReq);
    try auth.initializeDeadlines(200);
    try auth.noteActivity(205);
    try std.testing.expect((try auth.tick(219)) == null);
    try std.testing.expectEqual(TimeoutOutcome.Authentication, (try auth.tick(220)).?);

    var idle = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer idle.deinit();
    idle.session.setSessionState(.ChannelActive);
    try idle.initializeDeadlines(300);
    try idle.noteActivity(310);
    try std.testing.expect((try idle.tick(339)) == null);
    try std.testing.expectEqual(TimeoutOutcome.TotalSession, (try idle.tick(340)).?);

    const idle_limits = ResourceLimits{ .deadlines = .{ .idle = 30, .total_session = 100 } };
    var idle_only = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, idle_limits);
    defer idle_only.deinit();
    idle_only.session.setSessionState(.ChannelActive);
    try idle_only.initializeDeadlines(400);
    try idle_only.noteActivity(410);
    try std.testing.expect((try idle_only.tick(439)) == null);
    try std.testing.expectEqual(TimeoutOutcome.Idle, (try idle_only.tick(440)).?);

    var monotonic = try SshzClient.initWithLimits(prng.random(), "test", std.testing.allocator, limits);
    defer monotonic.deinit();
    try monotonic.initializeDeadlines(500);
    try std.testing.expectError(error.DeadlinesAlreadyInitialized, monotonic.initializeDeadlines(501));
    try monotonic.noteActivity(510);
    try std.testing.expectError(error.NonMonotonicTime, monotonic.tick(509));
}

test "deadline phase transition precedes expiration of the prior phase" {
    const limits = ResourceLimits{ .deadlines = .{
        .handshake = 10,
        .authentication = 20,
    } };
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.initWithLimits(
        prng.random(),
        "test",
        std.testing.allocator,
        limits,
    );
    defer client.deinit();

    try client.initializeDeadlines(0);
    client.session.setSessionState(.AuthServReq);

    try std.testing.expect((try client.tick(10)) == null);
    try std.testing.expectEqual(DeadlinePhase.Authentication, client.deadline_state.phase);
    try std.testing.expectEqual(@as(u64, 10), client.deadline_state.phase_started_at);
    try std.testing.expect((try client.tick(29)) == null);
    try std.testing.expectEqual(TimeoutOutcome.Authentication, (try client.tick(30)).?);
}

test "SshzClientEventCodes Banner variant" {
    const banner: SshzClientEventCodes = .{ .Banner = "Welcome to the server" };
    switch (banner) {
        .Banner => |text| {
            try std.testing.expectEqualStrings("Welcome to the server", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "SshzClientEventCodes agent forwarding variants" {
    const open_evt: SshzClientEventCodes = .{ .AgentChannelOpen = 3 };
    switch (open_evt) {
        .AgentChannelOpen => |channel| try std.testing.expectEqual(@as(u32, 3), channel),
        else => return error.TestUnexpectedResult,
    }

    const data_evt: SshzClientEventCodes = .{ .AgentData = .{ .channel = 3, .data = "agent-data" } };
    switch (data_evt) {
        .AgentData => |data| {
            try std.testing.expectEqual(@as(u32, 3), data.channel);
            try std.testing.expectEqualStrings("agent-data", data.data);
        },
        else => return error.TestUnexpectedResult,
    }

    const closed_evt: SshzClientEventCodes = .{ .AgentChannelClosed = 3 };
    switch (closed_evt) {
        .AgentChannelClosed => |channel| try std.testing.expectEqual(@as(u32, 3), channel),
        else => return error.TestUnexpectedResult,
    }
}

test "SshzClientEventCodes ordinary channel lifecycle variants" {
    const eof_event: SshzClientEventCodes = .{ .ChannelEof = 5 };
    switch (eof_event) {
        .ChannelEof => |channel| try std.testing.expectEqual(@as(u32, 5), channel),
        else => return error.TestUnexpectedResult,
    }

    const closed_event: SshzClientEventCodes = .{ .ChannelClosed = 7 };
    switch (closed_event) {
        .ChannelClosed => |channel| try std.testing.expectEqual(@as(u32, 7), channel),
        else => return error.TestUnexpectedResult,
    }
}

test "ExtendedData struct" {
    const ext: ExtendedData = .{ .data_type = 1, .data = "stderr output" };
    try std.testing.expectEqual(@as(u32, 1), ext.data_type);
    try std.testing.expectEqualStrings("stderr output", ext.data);
}

test "WindowSize struct" {
    const ws: WindowSize = .{ .channel = 0, .cols = 120, .rows = 40, .width_px = 960, .height_px = 640 };
    try std.testing.expectEqual(@as(u32, 120), ws.cols);
    try std.testing.expectEqual(@as(u32, 40), ws.rows);
}

test "SshzServerEventCodes WindowChange variant" {
    const evt: SshzServerEventCodes = .{ .WindowChange = .{ .channel = 0, .cols = 80, .rows = 24, .width_px = 640, .height_px = 480 } };
    switch (evt) {
        .WindowChange => |ws| {
            try std.testing.expectEqual(@as(u32, 80), ws.cols);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "SshzServerEventCodes Signal variant" {
    const evt: SshzServerEventCodes = .{ .Signal = .{ .channel = 0, .name = "INT" } };
    switch (evt) {
        .Signal => |sig| {
            try std.testing.expectEqualStrings("INT", sig.name);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Exec variant" {
    const req: ChannelRequestType = .{ .Exec = "ls -la" };
    switch (req) {
        .Exec => |cmd| try std.testing.expectEqualStrings("ls -la", cmd),
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Subsystem variant" {
    const req: ChannelRequestType = .{ .Subsystem = "sftp" };
    switch (req) {
        .Subsystem => |name| try std.testing.expectEqualStrings("sftp", name),
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Env variant" {
    const req: ChannelRequestType = .{ .Env = .{ .name = "LANG", .value = "en_US.UTF-8" } };
    switch (req) {
        .Env => |env| {
            try std.testing.expectEqualStrings("LANG", env.name);
            try std.testing.expectEqualStrings("en_US.UTF-8", env.value);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Shell variant" {
    const req: ChannelRequestType = .Shell;
    switch (req) {
        .Shell => {},
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType AgentForward variant" {
    const req: ChannelRequestType = .AgentForward;
    switch (req) {
        .AgentForward => {},
        else => return error.TestUnexpectedResult,
    }
}

test "KeyboardInteractivePrompt struct" {
    const prompt: KeyboardInteractivePrompt = .{
        .name = "Login",
        .instruction = "Enter credentials",
        .prompt = "Password: ",
        .echo = false,
    };
    try std.testing.expectEqualStrings("Password: ", prompt.prompt);
    try std.testing.expect(!prompt.echo);
}

test "UserCredentialsPasswordOrPubkey password variant" {
    const auth: UserCredentialsPasswordOrPubkey = .{ .Password = "secret" };
    switch (auth) {
        .Password => |password| try std.testing.expectEqualStrings("secret", password),
        else => return error.TestUnexpectedResult,
    }
}

test "client-server full handshake round-trip" {
    const privkey = @import("privkey.zig");

    var cprng = std.Random.DefaultPrng.init(1);
    var sprng = std.Random.DefaultPrng.init(2);

    var client = try SshzClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    try client.setTryNoneAuth(true);
    var server = try SshzServer.init(sprng.random(), privkey.testkey_valid, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [16384]u8 = undefined;
    var s2c_buf: [16384]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;
    var event_order: usize = 0;
    var identification_order: ?usize = null;
    var host_key_order: ?usize = null;
    var auth_order: ?usize = null;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 500) : (steps += 1) {
        if (connected_client) break;

        for (endpoints) |ep| {
            const is_client = ep == .client_ep;

            if (is_client) {
                const cev = client.getNextEvent() catch continue;
                switch (cev) {
                    .ReadyToProduce => {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (s2c_len > 0) {
                            const feed = @min(n, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                        if (s2c_len > 0) {
                            const feed = @min(s.consume, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .ServerIdentification => {
                            identification_order = event_order;
                            event_order += 1;
                            client.clearEvent(code) catch {};
                        },
                        .AuthMethodStarted => {
                            auth_order = event_order;
                            event_order += 1;
                            client.clearEvent(code) catch {};
                        },
                        .CheckHostKey => {
                            host_key_order = event_order;
                            event_order += 1;
                            client.acceptHostKey() catch {};
                        },
                        .GetPrivateKey => {
                            client.clearEvent(.GetPrivateKey) catch {};
                        },
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .EndSession => {
                            connected_client = false;
                            break;
                        },
                        else => {},
                    },
                }
            } else {
                const sev = server.getNextEvent() catch continue;
                switch (sev) {
                    .ReadyToProduce => {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (c2s_len > 0) {
                            const feed = @min(n, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                        if (c2s_len > 0) {
                            const feed = @min(s.consume, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .UserAuth => {
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .ChannelOpenRequest => |request| {
                            server.acceptChannelOpen(request.channel) catch {};
                        },
                        .Connected => {
                            server.clearEvent(.{ .Connected = 0 }) catch {};
                        },
                        .ChannelRequest => {
                            server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {};
                        },
                        else => {},
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(identification_order.? < host_key_order.?);
    try std.testing.expect(host_key_order.? < auth_order.?);
    try std.testing.expect(!client.session.ecdh_ephem_keypair_active);
    try std.testing.expect(!server.session.ecdh_ephem_keypair_active);
    try std.testing.expect(!client.session.kex_hasher.active);
    try std.testing.expect(!server.session.kex_hasher.active);
    for (client.session.shared_secret_k) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (server.session.shared_secret_k) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "HostKeyInfo fingerprint computation" {
    const Sshz = @import("sshz.zig");
    const key_data = "test-host-key-data";
    var fp: [Protocol.hash_algo.digest_length]u8 = undefined;
    Protocol.hash_algo.hash(key_data, &fp, .{});

    const info: Sshz.HostKeyInfo = .{
        .raw_key = key_data,
        .fingerprint = fp,
    };

    var buf: [44]u8 = undefined;
    const fp_str = info.fingerprintStr(&buf);
    // SHA-256 of "test-host-key-data" base64-encoded should be 44 chars
    try std.testing.expectEqual(@as(usize, 44), fp_str.len);
    try std.testing.expect(fp_str[0] != 0); // not empty
}

test "HostKeyInfo fingerprint is deterministic" {
    const key = "same-key";
    var fp1: [Protocol.hash_algo.digest_length]u8 = undefined;
    var fp2: [Protocol.hash_algo.digest_length]u8 = undefined;
    Protocol.hash_algo.hash(key, &fp1, .{});
    Protocol.hash_algo.hash(key, &fp2, .{});
    try std.testing.expectEqualSlices(u8, &fp1, &fp2);
}

fn prepareHostKeyDecision(client: *SshzClient, raw_key: []const u8) !HostKeyInfo {
    client.session.hostkey_ks = try std.testing.allocator.dupe(u8, raw_key);
    var fingerprint: [Protocol.hash_algo.digest_length]u8 = undefined;
    Protocol.hash_algo.hash(raw_key, &fingerprint, .{});
    const info: HostKeyInfo = .{
        .raw_key = client.session.hostkey_ks,
        .fingerprint = fingerprint,
    };
    client.session.setSessionState(.HostKeyDecision);
    client.session.setIoSessionState(.Idle);
    client.requestEvent(.{ .CheckHostKey = info }, .Idle);
    return info;
}

test "client explicitly accepts a pending host key" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    _ = try prepareHostKeyDecision(&client, "accepted-host-key");

    try client.acceptHostKey();

    try std.testing.expectEqual(ClientSessionState.NewKeysRead, client.session.sessionState);
    try std.testing.expectEqual(@as(u8, 0), client.session.auth_attempts_total);
    try std.testing.expect(client.iostate_wr == .Idle);
}

test "client explicitly rejects a pending host key before authentication" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    const expected = try prepareHostKeyDecision(&client, "rejected-host-key");

    try client.rejectHostKey();

    try std.testing.expectEqual(ClientSessionState.HostKeyRejected, client.session.sessionState);
    try std.testing.expectEqual(@as(u8, 0), client.session.auth_attempts_total);
    const event = try client.getNextEvent();
    switch (event) {
        .Event => |code| switch (code) {
            .EndSession => |reason| switch (reason) {
                .HostKeyRejected => |info| {
                    try std.testing.expectEqualSlices(u8, expected.raw_key.?, info.raw_key.?);
                    try std.testing.expectEqualSlices(u8, &expected.fingerprint, &info.fingerprint);
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "clearing a host key event without a decision fails closed" {
    var prng = std.Random.DefaultPrng.init(42);
    var client = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    _ = try prepareHostKeyDecision(&client, "pending-host-key");

    const first = try client.getNextEvent();
    switch (first) {
        .Event => |code| try std.testing.expectError(IoError.badClearEvent, client.clearEvent(code)),
        else => return error.TestUnexpectedResult,
    }
    try client.advance();

    try std.testing.expectEqual(ClientSessionState.HostKeyDecision, client.session.sessionState);
    try std.testing.expectEqual(@as(u8, 0), client.session.auth_attempts_total);
    const still_pending = try client.getNextEvent();
    switch (still_pending) {
        .Event => |code| try std.testing.expect(code == .CheckHostKey),
        else => return error.TestUnexpectedResult,
    }
}

test "init sets both iostates to Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_rd);
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_wr);
    try std.testing.expectEqual(@as(usize, 0), m.rd_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.rd_off);
    try std.testing.expectEqual(@as(usize, 0), m.wr_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.wr_off);
}

test "deinit zeros both buffers" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);

    @memset(&m.iobuf_rd, 0xAA);
    @memset(&m.iobuf_wr, 0xBB);

    m.deinit();

    for (m.iobuf_rd) |b| try std.testing.expectEqual(@as(u8, 0), b);
    for (m.iobuf_wr) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "deadline fail-closed scrubs session credentials keys and packet buffers" {
    const limits = ResourceLimits{ .deadlines = .{ .handshake = 1 } };
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.initWithLimits(prng.random(), "testuser", std.testing.allocator, limits);

    try m.setPrivateKey("copied-private-key");
    try m.setPrivateKeyPassphrase("copied-key-passphrase");
    try m.setAuthPassphrase("copied-password");
    @memset(&m.iobuf_rd, 0xA5);
    @memset(&m.iobuf_wr, 0x5A);
    @memset(&m.iobuf_decompressed, 0xCC);
    @memset(&m.session.shared_secret_k, 0x33);
    @memset(std.mem.asBytes(&m.session.ecdh_ephem_keypair), 0x44);
    m.session.ecdh_ephem_keypair_active = true;

    try m.initializeDeadlines(10);
    try std.testing.expectEqual(TimeoutOutcome.Handshake, (try m.tick(11)).?);
    try std.testing.expect(m.terminated);
    try std.testing.expect(m.session.privkey_ascii == null);
    try std.testing.expect(m.session.privkey_passphrase == null);
    try std.testing.expect(m.session.auth_passphrase == null);
    try std.testing.expect(!m.session.ecdh_ephem_keypair_active);
    try std.testing.expect(!m.session.kex_hasher.active);
    for (m.iobuf_rd) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (m.iobuf_wr) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (m.iobuf_decompressed) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (m.session.shared_secret_k) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    try std.testing.expectEqual(TimeoutOutcome.Handshake, (try m.tick(12)).?);
    m.deinit();
    m.deinit();
}

test "requestRead sets iostate_rd, leaves iostate_wr unchanged" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestRead(0, 10, .ReadPktHdr);

    try std.testing.expect(m.iostate_rd != .Idle);
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_wr);
    try std.testing.expectEqual(@as(usize, 0), m.rd_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.rd_off);
}

test "requestWrite sets iostate_wr, leaves iostate_rd unchanged" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Simulate data in write buffer
    const data = "hello";
    @memcpy(m.iobuf_wr[0..data.len], data);
    try m.requestWrite(m.iobuf_wr[0..data.len], .Idle);

    try std.testing.expect(m.iostate_wr != .Idle);
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_rd);
    try std.testing.expectEqual(@as(usize, data.len), m.wr_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.wr_off);
}

test "requestEvent sets iostate_wr to Eventing" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);

    switch (m.iostate_wr) {
        .Active => |step| {
            switch (step.action) {
                .Eventing => {},
                else => return error.TestUnexpectedResult,
            }
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_rd);
}

test "write feeds data into iobuf_rd" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestRead(0, 5, .ReadPktHdr);
    try m.write("hel");
    try std.testing.expectEqual(@as(usize, 3), m.rd_nbytes);
    try std.testing.expectEqualStrings("hel", m.iobuf_rd[0..3]);
}

test "write rejects data when iostate_rd is Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.write("data");
    try std.testing.expectError(IoError.cannotAcceptWrite, result);
}

test "peek reads from iobuf_wr" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const msg = "world";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    try m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);

    const data = try m.peek(msg.len);
    try std.testing.expectEqualStrings(msg, data);
}

test "peek fails when iostate_wr is Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.peek(1);
    try std.testing.expectError(IoError.notProducing, result);
}

test "consumed advances wr_off" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const msg = "abcde";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    try m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);

    try m.consumed(2);
    try std.testing.expectEqual(@as(usize, 2), m.wr_off);
}

test "consumed fails when iostate_wr is Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.consumed(1);
    try std.testing.expectError(IoError.notProducing, result);
}

test "getNextEvent returns Event when Eventing" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);
    const ev = try m.getNextEvent();
    switch (ev) {
        .Event => |code| switch (code) {
            .Connected => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "getNextEvent returns ReadyToConsume when only read is active" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Set ioSessionState to ReadPktHdr so advance() doesn't try to process Idle
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 10, .ReadPktHdr);
    const ev = try m.getNextEvent();
    switch (ev) {
        .ReadyToConsume => |n| try std.testing.expectEqual(@as(usize, 10), n),
        else => return error.TestUnexpectedResult,
    }
}

test "getNextEvent returns ReadyToProduce when only write is active" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Set ioSessionState to Idle; with write active, canProcessIoSessionState(.Idle)
    // requires both idle, so advance won't process it
    m.session.setIoSessionState(.Idle);
    const msg = "data";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    try m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);
    const ev = try m.getNextEvent();
    switch (ev) {
        .ReadyToProduce => |n| try std.testing.expectEqual(@as(usize, msg.len), n),
        else => return error.TestUnexpectedResult,
    }
}

test "getNextEvent returns ReadyToConsumeAndProduce when both active" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 10, .ReadPktHdr);
    const msg = "data";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    try m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);

    const ev = try m.getNextEvent();
    switch (ev) {
        .ReadyToConsumeAndProduce => |s| {
            try std.testing.expectEqual(@as(usize, 10), s.consume);
            try std.testing.expectEqual(@as(usize, msg.len), s.produce);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "clearEvent resets iostate_wr from Eventing to Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);
    try std.testing.expect(m.iostate_wr != .Idle);

    try m.clearEvent(.Connected);
    // After clearing, advance() runs and may set new states,
    // but the event was cleared successfully (no error returned)
}

test "clearEvent fails for wrong event code" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);
    const result = m.clearEvent(.GetPrivateKey);
    try std.testing.expectError(IoError.badClearEvent, result);
}

test "clearEvent fails when not eventing" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.clearEvent(.Connected);
    try std.testing.expectError(IoError.badClearEvent, result);
}

test "read and write buffers are independent" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Fill read buffer
    @memset(&m.iobuf_rd, 0x11);
    // Fill write buffer
    @memset(&m.iobuf_wr, 0x22);

    // Verify they don't alias
    try std.testing.expectEqual(@as(u8, 0x11), m.iobuf_rd[0]);
    try std.testing.expectEqual(@as(u8, 0x22), m.iobuf_wr[0]);
    try std.testing.expect(&m.iobuf_rd[0] != &m.iobuf_wr[0]);
}

test "simultaneous read and write I/O: data does not cross-contaminate" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.ReadPktHdr);

    // Start a read (consuming 5 bytes)
    m.requestRead(0, 5, .ReadPktHdr);

    // Start a write (producing 3 bytes)
    const wr_data = "abc";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    try m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);

    // Feed data to read side
    try m.write("xy");
    try std.testing.expectEqual(@as(usize, 2), m.rd_nbytes);
    try std.testing.expectEqualStrings("xy", m.iobuf_rd[0..2]);

    // Drain data from write side
    const peeked = try m.peek(3);
    try std.testing.expectEqualStrings("abc", peeked);
    try m.consumed(3);

    // Write side done, read side still has 3 bytes to go
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_wr);
    try std.testing.expect(m.iostate_rd != .Idle);
}

test "canProcessIoSessionState: Idle requires both sides idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.Idle);
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;
    try std.testing.expect(m.canProcessIoSessionState());

    // If read is active, Idle should not be processable
    m.requestRead(0, 1, .ReadPktHdr);
    try std.testing.expect(!m.canProcessIoSessionState());
}

test "canProcessIoSessionState: ReadPktHdr only needs read idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.ReadPktHdr);
    m.iostate_rd = .Idle;
    // Write side active should not block read states
    const wr_data = "x";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    try m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);

    try std.testing.expect(m.canProcessIoSessionState());
}

test "canProcessIoSessionState: VersionWrite needs write idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.VersionWrite);
    m.iostate_wr = .Idle;
    try std.testing.expect(m.canProcessIoSessionState());

    const wr_data = "x";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    try m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);
    try std.testing.expect(!m.canProcessIoSessionState());
}

test "canProcessIoSessionState: ReadPktCompletion needs write idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.{ .ReadPktCompletion = m.iobuf_rd[0..0] });
    m.iostate_wr = .Idle;
    try std.testing.expect(m.canProcessIoSessionState());

    // With write active, ReadPktCompletion should be blocked
    const wr_data = "x";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    try m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);
    try std.testing.expect(!m.canProcessIoSessionState());
}

test "ReadyToConsumeAndProduce struct fields" {
    const ev = SshzEvent(.Client){ .ReadyToConsumeAndProduce = .{ .consume = 100, .produce = 50 } };
    switch (ev) {
        .ReadyToConsumeAndProduce => |s| {
            try std.testing.expectEqual(@as(usize, 100), s.consume);
            try std.testing.expectEqual(@as(usize, 50), s.produce);
        },
        else => return error.TestUnexpectedResult,
    }
}

fn largeChannelTestByte(packet_index: u8, byte_index: usize) u8 {
    var value: u32 = @intCast(byte_index);
    value = value *% 1664525 +% 1013904223 +% packet_index;
    return @truncate(value >> 24);
}

test "full handshake handles large compressed channel packets and keepalive queued through rekey" {
    const privkey = @import("privkey.zig");
    const limits = ResourceLimits{ .key_lifetime = .{
        .rekey_after_encrypted_packets = 10,
    } };

    var cprng = std.Random.DefaultPrng.init(10);
    var sprng = std.Random.DefaultPrng.init(20);

    var client = try SshzClient.initWithLimits(
        cprng.random(),
        "testuser",
        std.testing.allocator,
        limits,
    );
    defer client.deinit();
    var server = try SshzServer.initWithLimits(
        sprng.random(),
        privkey.testkey_valid,
        std.testing.allocator,
        limits,
    );
    defer server.deinit();

    var c2s_buf: [16384]u8 = undefined;
    var s2c_buf: [Protocol.MaxSSHPacket]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;
    var connected_server = false;
    var server_packets_sent: u8 = 0;
    var client_packets_received: u8 = 0;
    var receive_epochs: [12]u64 = .{0} ** 12;
    var initial_session_id: ?[Protocol.hash_algo.digest_length]u8 = null;
    var accepted_host_fingerprint: ?[Protocol.hash_algo.digest_length]u8 = null;
    var keepalive_token: ?KeepaliveToken = null;
    var keepalive_acknowledged = false;
    const packet_lengths = [_]usize{
        12_000, 6_000, 3_000, 3_000, 3_000, 3_000,
        3_000,  3_000, 3_000, 3_000, 3_000, 3_000,
    };

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 4000) : (steps += 1) {
        if (client_packets_received == packet_lengths.len and
            receive_epochs[packet_lengths.len - 1] > receive_epochs[0] and
            !client.session.is_rekeying and !server.session.is_rekeying and
            keepalive_acknowledged)
            break;

        for (endpoints) |ep| {
            if (ep == .client_ep) {
                if (connected_client and keepalive_token == null and
                    client.keyLifetimeStatus().rekey_in_progress)
                {
                    keepalive_token = try client.requestKeepalive();
                    try std.testing.expectEqual(
                        KeepaliveTransmission.Queued,
                        (try client.keepaliveStatus(keepalive_token.?)).transmission,
                    );
                }
                const cev = client.getNextEvent() catch continue;
                switch (cev) {
                    .ReadyToProduce, .ReadyToConsumeAndProduce => {
                        const data = try client.peek(31);
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        try client.consumed(data.len);
                    },
                    .ReadyToConsume => |n| {
                        if (s2c_len > 0) {
                            const feed = @min(n, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .CheckHostKey => client.acceptHostKey() catch {},
                        .GetPrivateKey => client.clearEvent(.GetPrivateKey) catch {},
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            initial_session_id = client.session.session_id;
                            var fingerprint: [Protocol.hash_algo.digest_length]u8 = undefined;
                            Protocol.hash_algo.hash(client.session.hostkey_ks.?, &fingerprint, .{});
                            accepted_host_fingerprint = fingerprint;
                            client.clearEvent(.Connected) catch {};
                        },
                        .RxData => |channel_data| {
                            const packet_index: usize = client_packets_received;
                            try std.testing.expect(packet_index < packet_lengths.len);
                            receive_epochs[packet_index] = client.keyLifetimeStatus().inbound.epoch;
                            try std.testing.expectEqual(packet_lengths[packet_index], channel_data.data.len);
                            for (channel_data.data, 0..) |byte, byte_index| {
                                try std.testing.expectEqual(
                                    largeChannelTestByte(@intCast(packet_index), byte_index),
                                    byte,
                                );
                            }
                            client_packets_received += 1;
                            client.clearEvent(.{ .RxData = channel_data }) catch {};
                        },
                        .EndSession => break,
                        else => {
                            client.clearEvent(code) catch {};
                        },
                    },
                }
                if (keepalive_token) |token| {
                    const status = try client.keepaliveStatus(token);
                    // c2s_buf is still a caller-owned unsent queue. Handoff
                    // alone must not claim a transport flush.
                    try std.testing.expect(!status.transport_flushed);
                    if (status.outcome == .Acknowledged) {
                        try std.testing.expectEqual(KeepaliveReply.Failure, status.outcome.Acknowledged);
                        try std.testing.expectEqual(KeepaliveTransmission.HandedToTransport, status.transmission);
                        keepalive_acknowledged = true;
                    }
                }
            } else {
                const sev = server.getNextEvent() catch continue;
                switch (sev) {
                    .ReadyToProduce, .ReadyToConsumeAndProduce => {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (c2s_len > 0) {
                            const feed = @min(n, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .UserAuth => {
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .ChannelOpenRequest => |request| {
                            server.acceptChannelOpen(request.channel) catch {};
                        },
                        .Connected => {
                            connected_server = true;
                            server.clearEvent(.{ .Connected = 0 }) catch {};
                        },
                        .ChannelRequest => server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {},
                        else => {
                            server.clearEvent(code) catch {};
                        },
                    },
                }

                if (connected_server and server_packets_sent < packet_lengths.len and server.iostate_wr == .Idle and s2c_len == 0) {
                    const buf = server.getChannelWriteBuffer(0) catch continue;
                    const packet_index: usize = server_packets_sent;
                    const packet_len = packet_lengths[packet_index];
                    if (buf.len >= packet_len) {
                        for (buf[0..packet_len], 0..) |*byte, byte_index| {
                            byte.* = largeChannelTestByte(@intCast(packet_index), byte_index);
                        }
                        server.channelWriteComplete(0, packet_len) catch continue;
                        server_packets_sent += 1;
                    }
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(connected_server);
    try std.testing.expect(keepalive_acknowledged);
    try std.testing.expectEqual(@as(u8, packet_lengths.len), client_packets_received);
    try std.testing.expect(receive_epochs[0] >= 1);
    try std.testing.expect(receive_epochs[packet_lengths.len - 1] > receive_epochs[0]);
    try std.testing.expect(client.keyLifetimeStatus().inbound.epoch >= 2);
    try std.testing.expect(server.keyLifetimeStatus().outbound.epoch >= 2);
    try std.testing.expectEqualSlices(u8, &initial_session_id.?, &client.session.session_id);
    var final_host_fingerprint: [Protocol.hash_algo.digest_length]u8 = undefined;
    Protocol.hash_algo.hash(client.session.hostkey_ks.?, &final_host_fingerprint, .{});
    try std.testing.expectEqualSlices(
        u8,
        &accepted_host_fingerprint.?,
        &final_host_fingerprint,
    );
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, client.session.keydata.c2s.compression.algorithm);
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, client.session.keydata.s2c.compression.algorithm);
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, server.session.keydata.c2s.compression.algorithm);
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, server.session.keydata.s2c.compression.algorithm);
    try std.testing.expect(client.session.keydata.c2s.compression.active);
    try std.testing.expect(client.session.keydata.s2c.compression.active);
    try std.testing.expect(server.session.keydata.c2s.compression.active);
    try std.testing.expect(server.session.keydata.s2c.compression.active);
}

test "client channelWriteComplete uses direct write when read is active" {
    const privkey = @import("privkey.zig");

    var cprng = std.Random.DefaultPrng.init(100);
    var sprng = std.Random.DefaultPrng.init(200);

    var client = try SshzClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try SshzServer.init(sprng.random(), privkey.testkey_valid, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [16384]u8 = undefined;
    var s2c_buf: [16384]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;
    var sent_channel_data = false;
    var duplex_event_seen = false;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 1000) : (steps += 1) {
        if (sent_channel_data and duplex_event_seen) break;

        for (endpoints) |ep| {
            if (ep == .client_ep) {
                const cev = client.getNextEvent() catch continue;
                switch (cev) {
                    .ReadyToProduce => {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        // After connecting, try to send channel data while reading
                        if (connected_client and !sent_channel_data) {
                            const buf = client.getChannelWriteBuffer(0) catch continue;
                            if (buf.len > 0) {
                                const msg = "keyboard-input";
                                @memcpy(buf[0..msg.len], msg);
                                client.channelWriteComplete(0, msg.len) catch {};
                                sent_channel_data = true;
                            }
                        }
                        if (s2c_len > 0) {
                            const feed = @min(n, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        duplex_event_seen = true;
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                        if (s2c_len > 0) {
                            const feed = @min(s.consume, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .CheckHostKey => client.acceptHostKey() catch {},
                        .GetPrivateKey => client.clearEvent(.GetPrivateKey) catch {},
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .EndSession => break,
                        else => {
                            client.clearEvent(code) catch {};
                        },
                    },
                }
            } else {
                const sev = server.getNextEvent() catch continue;
                switch (sev) {
                    .ReadyToProduce, .ReadyToConsumeAndProduce => {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (c2s_len > 0) {
                            const feed = @min(n, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .UserAuth => {
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .ChannelOpenRequest => |request| {
                            server.acceptChannelOpen(request.channel) catch {};
                        },
                        .Connected => server.clearEvent(.{ .Connected = 0 }) catch {},
                        .ChannelRequest => server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {},
                        else => {
                            server.clearEvent(code) catch {};
                        },
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(sent_channel_data);
}

fn driveHandshakeForKeys(hostkey_ascii: []const u8, client_key_ascii: ?[]const u8, expected_pubkey_algorithm: ?[]const u8) !void {
    var cprng = std.Random.DefaultPrng.init(1000);
    var sprng = std.Random.DefaultPrng.init(2000);

    var client = try SshzClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try SshzServer.init(sprng.random(), hostkey_ascii, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [65536]u8 = undefined;
    var s2c_buf: [65536]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;
    var connected_client = false;
    var saw_expected_pubkey = expected_pubkey_algorithm == null;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 2000) : (steps += 1) {
        if (connected_client and saw_expected_pubkey) break;

        for (endpoints) |ep| {
            if (ep == .client_ep) {
                const cev = client.getNextEvent() catch continue;
                switch (cev) {
                    .ReadyToProduce => {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (s2c_len > 0) {
                            const feed = @min(n, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                        if (s2c_len > 0) {
                            const feed = @min(s.consume, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .CheckHostKey => client.acceptHostKey() catch {},
                        .GetPrivateKey => {
                            if (client_key_ascii) |key| client.setPrivateKey(key) catch {};
                            client.clearEvent(.GetPrivateKey) catch {};
                        },
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .EndSession => break,
                        else => {
                            client.clearEvent(code) catch {};
                        },
                    },
                }
            } else {
                const sev = server.getNextEvent() catch continue;
                switch (sev) {
                    .ReadyToProduce => {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (c2s_len > 0) {
                            const feed = @min(n, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                        if (c2s_len > 0) {
                            const feed = @min(s.consume, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .UserAuth => |credentials| {
                            if (expected_pubkey_algorithm) |expected| {
                                if (credentials.auth) |auth| switch (auth) {
                                    .Pubkey => |pubkey| {
                                        try std.testing.expectEqualStrings(expected, pubkey.algorithm);
                                        try std.testing.expect(pubkey.blob.len > 0);
                                        saw_expected_pubkey = true;
                                    },
                                    else => {},
                                };
                            }
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .ChannelOpenRequest => |request| {
                            server.acceptChannelOpen(request.channel) catch {};
                        },
                        .Connected => server.clearEvent(.{ .Connected = 0 }) catch {},
                        .ChannelRequest => server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {},
                        else => {
                            server.clearEvent(code) catch {};
                        },
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(saw_expected_pubkey);
}

test "handshake supports ECDSA and RSA host keys" {
    const privkey = @import("privkey.zig");
    try driveHandshakeForKeys(privkey.testkey_ecdsa_p256, null, null);
    try driveHandshakeForKeys(privkey.testkey_rsa_2048, null, null);
}

test "public key auth supports Ed25519 ECDSA and RSA SHA2 keys" {
    const privkey = @import("privkey.zig");
    try driveHandshakeForKeys(privkey.testkey_valid, privkey.testkey_valid, "ssh-ed25519");
    try driveHandshakeForKeys(privkey.testkey_valid, privkey.testkey_ecdsa_p256, "ecdsa-sha2-nistp256");
    try driveHandshakeForKeys(privkey.testkey_valid, privkey.testkey_rsa_2048, "rsa-sha2-512");
}
