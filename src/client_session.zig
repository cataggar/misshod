const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const UNSAFE_TRACEDUMP = util.unsafeTracedump;
const Sshz = @import("sshz.zig");
const SshzClient = Sshz.SshzClient;
const SshzError = Sshz.SshzError;
const IoError = Sshz.IoError;
const AuthMethod = Sshz.AuthMethod;
const AuthFailureInfo = Sshz.AuthFailureInfo;
const SshOpenFailureReason = Sshz.SshOpenFailureReason;
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;
const BufferReader = @import("buffer.zig").BufferReader;
const Hasher = @import("hasher.zig").Hasher;
const AesCtr = @import("aesctr.zig").AesCtr;
const decodeOpenSshPrivateKey = @import("privkey.zig").decodeOpenSshPrivateKey;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Key = @import("key.zig");
const Protocol = @import("protocol.zig");
const Channel = @import("channel.zig").Channel;
const ChannelControl = @import("channel.zig").ChannelControl;
const MaxChannels = @import("channel.zig").MaxChannels;
const ChannelTable = @import("channel.zig").ChannelTable;
const ChannelState = @import("channel.zig").ChannelState;
const ClientChannelOpenMode = @import("channel.zig").ClientChannelOpenMode;
const ChannelType = @import("channel.zig").ChannelType;
const TcpipOpen = @import("channel.zig").TcpipOpen;

const OwnedExitSignal = struct {
    signal_name: []u8,
    core_dumped: bool,
    error_message: []u8,
    language_tag: []u8,
};

const OwnedExitResult = union(enum) {
    Status: u32,
    Signal: OwnedExitSignal,
    NoResult,
};

const ExitResultSlot = struct {
    channel_id: u32,
    completed: bool = false,
    result: ?OwnedExitResult = null,
};

const PendingChannelReply = struct {
    remote_id: u32,
    success: bool,
};

pub const SessionState = enum {
    Init,
    KexInitWrite,
    KexInitRead,
    EcdhInitWrite,
    EcdhReply,
    CheckHostKey,
    HostKeyDecision,
    HostKeyRejected,
    NewKeysRead,
    NewKeysWrite,
    AuthServReq,
    AuthServRsp,
    AuthStart,
    NoneAuthReq,
    GetPrivateKeyCompleted,
    PubkeyAuthDecodeKeyPasswordless,
    PubkeyAuthDecodeKeyPassword,
    PubkeyAuthStart,
    PubkeyAuthReq,
    AuthMethodQueued,
    AuthRsp,
    PasswordAuthStart,
    PasswordAuthReq,
    KeyboardInteractiveAuthStart,
    KeyboardInteractiveAuthReq,
    KeyboardInteractiveInfoRsp,
    ChannelOpenReq,
    ChannelOpenRsp,
    ChannelActive,
};

const PendingGlobalRequestKind = enum {
    TcpipForward,
    CancelTcpipForward,
    Keepalive,
};

const PendingGlobalRequest = struct {
    kind: PendingGlobalRequestKind,
    bind_address: []const u8 = "",
    bind_port: u32 = 0,
    transmission: Sshz.KeepaliveTransmission = .Emitting,
};

const MaxAuthAttemptsPerMethod: u8 = 1;
const MaxAuthAttemptsTotal: u8 = 8;

pub const Session = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    limits: Sshz.ResourceLimits,
    ioSessionState: Protocol.IoSessionState,
    sessionState: SessionState,

    // Owned only while an ECDH exchange is in progress.
    ecdh_ephem_keypair: Protocol.kex_algo.KeyPair = std.mem.zeroes(Protocol.kex_algo.KeyPair),
    ecdh_ephem_keypair_active: bool,
    // In form U32LenString("ssh-ed25519"), U32LenString(secret)
    hostkey_ks: ?[]u8 = null, // K_S, allocated
    shared_secret_k: [Protocol.kex_algo.shared_length]u8 = .{0} ** Protocol.kex_algo.shared_length, // K
    kex_hasher: Hasher(Protocol.hash_algo) = undefined, // for building H
    kex_hash_order: Protocol.KexHashOrder = .Init,
    selected_hostkey_algorithm: ?Key.SignatureAlgorithm,
    session_id: [Protocol.hash_algo.digest_length]u8 = .{0} ** Protocol.hash_algo.digest_length,
    session_id_established: bool = false,
    user_authenticated: bool = false,
    keydata: Protocol.KeyDataBi,
    username: []const u8,
    rand: std.Random = undefined,
    encrypted: bool,
    inbound_encrypted: bool,
    channel_table: ChannelTable,
    active_channel_id: ?u32,
    automatic_session_channel_id: ?u32,
    exit_results: [MaxChannels]?ExitResultSlot,
    pending_channel_replies: [MaxChannels]PendingChannelReply,
    pending_channel_replies_head: usize,
    pending_channel_replies_len: usize,
    pending_window_change: ?[4]u32,
    channel_window_adjust_in_flight: bool,
    pending_global_request: ?PendingGlobalRequest,
    keepalive: ?Sshz.KeepaliveStatus = null,
    last_keepalive_id: u64 = 0,
    global_requests_ended: bool = false,
    pending_global_request_bind_address: [Protocol.MaxSSHPacket]u8 = undefined,
    agent_forwarding_enabled: bool,
    agent_forwarding_requested: bool,
    auto_pty_requested: bool,
    auto_pty_term: ?[]u8,
    auto_pty_cols: u32,
    auto_pty_rows: u32,
    auto_pty_width_px: u32,
    auto_pty_height_px: u32,
    auto_exec_command: ?[]u8,
    auto_session_enabled: bool,
    auto_channel_read_credit_enabled: bool,
    kbd_interactive_response: ?[]u8, // allocated
    is_rekeying: bool,
    rekey_resume_state: ?SessionState,
    client_version: ?[]u8,
    server_version: ?[]u8,
    pre_identification_lines: usize,

    privkey_ascii: ?[]u8, // allocated
    privkey_passphrase: ?[]u8, //allocated
    auth_passphrase: ?[]u8, //allocated
    private_key: ?Key.PrivateKey,
    try_none_auth: bool,
    auth_attempts_total: u8,
    auth_stage: u8,
    auth_stage_attempts_by_method: [4]u8,
    current_auth_method: ?AuthMethod,
    last_auth_failure: ?AuthFailureInfo,
    pending_c2s_keys: ?Protocol.KeyDataUni,
    pending_s2c_keys: ?Protocol.KeyDataUni,
    negotiated_compression_c2s: Protocol.CompressionAlgorithm,
    negotiated_compression_s2c: Protocol.CompressionAlgorithm,
    pending_server_kexinit: ?[]u8,
    ignore_next_kex_packet: bool,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
        return initWithLimits(rand, username, allocator, .{});
    }

    pub fn initWithLimits(
        rand: std.Random,
        username: []const u8,
        allocator: std.mem.Allocator,
        limits: Sshz.ResourceLimits,
    ) !Self {
        try limits.validate();
        return .{
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .limits = limits,
            .username = username,
            .encrypted = false,
            .inbound_encrypted = false,
            .keydata = Protocol.KeyDataBi.init(),
            .kex_hasher = Hasher(Protocol.hash_algo).init(), // for hashing H
            .selected_hostkey_algorithm = null,
            .ecdh_ephem_keypair_active = false,
            .privkey_ascii = null,
            .privkey_passphrase = null,
            .auth_passphrase = null,
            .private_key = null,
            .channel_table = ChannelTable{ .limits = limits.channelLimits() },
            .active_channel_id = null,
            .automatic_session_channel_id = null,
            .exit_results = .{null} ** MaxChannels,
            .pending_channel_replies = undefined,
            .pending_channel_replies_head = 0,
            .pending_channel_replies_len = 0,
            .pending_window_change = null,
            .channel_window_adjust_in_flight = false,
            .pending_global_request = null,
            .agent_forwarding_enabled = false,
            .agent_forwarding_requested = false,
            .auto_pty_requested = false,
            .auto_pty_term = null,
            .auto_pty_cols = 80,
            .auto_pty_rows = 24,
            .auto_pty_width_px = 640,
            .auto_pty_height_px = 480,
            .auto_exec_command = null,
            .auto_session_enabled = true,
            .auto_channel_read_credit_enabled = true,
            .kbd_interactive_response = null,
            .is_rekeying = false,
            .rekey_resume_state = null,
            .client_version = try allocator.dupe(u8, Protocol.version),
            .server_version = null,
            .pre_identification_lines = 0,
            .try_none_auth = false,
            .auth_attempts_total = 0,
            .auth_stage = 0,
            .auth_stage_attempts_by_method = .{0} ** 4,
            .current_auth_method = null,
            .last_auth_failure = null,
            .pending_c2s_keys = null,
            .pending_s2c_keys = null,
            .negotiated_compression_c2s = .None,
            .negotiated_compression_s2c = .None,
            .pending_server_kexinit = null,
            .ignore_next_kex_packet = false,
        };
    }

    pub fn failClosed(self: *Self) void {
        self.clearAndFreeOptional(&self.privkey_ascii);
        self.clearAndFreeOptional(&self.privkey_passphrase);
        self.clearAndFreeOptional(&self.auth_passphrase);
        self.clearAndFreeOptional(&self.kbd_interactive_response);
        self.clearAndFreeOptional(&self.auto_exec_command);
        self.clearAndFreeOptional(&self.auto_pty_term);
        self.auto_pty_requested = false;
        self.clearPendingKeys();
        self.clearAndFreeOptional(&self.pending_server_kexinit);
        self.rekey_resume_state = null;
        self.is_rekeying = false;
        if (self.private_key) |*key| {
            key.clear();
            self.private_key = null;
        }
        self.channel_table.secureZeroAll();
        self.active_channel_id = null;
        self.automatic_session_channel_id = null;
        self.clearAllExitResults();
        self.pending_channel_replies_head = 0;
        self.pending_channel_replies_len = 0;
        self.channel_window_adjust_in_flight = false;
        self.endGlobalRequests();
        self.keydata.clear();
        self.clearKexState();
        std.crypto.secureZero(u8, &self.session_id);
        self.session_id_established = false;
        self.user_authenticated = false;
        self.encrypted = false;
        self.inbound_encrypted = false;
    }

    pub fn isActive(self: *const Self) bool {
        return self.sessionState == .ChannelActive;
    }

    fn validatePeerChannel(self: *const Self, window: u32, packet_size: u32) SshzError!void {
        if (window > self.limits.max_channel_window or packet_size == 0 or
            packet_size > self.limits.max_peer_packet_size)
            return IoError.InvalidChannelParameters;
    }

    fn pendingBufferedData(self: *const Self) usize {
        var total: usize = 0;
        for (self.channel_table.channels) |slot| {
            if (slot) |chan| total += chan.write_buf_nbytes;
        }
        return total;
    }

    pub fn deinit(self: *Self) void {
        self.endGlobalRequests();
        self.clearAndFreeOptional(&self.privkey_ascii);
        self.clearAndFreeOptional(&self.privkey_passphrase);
        self.clearAndFreeOptional(&self.auth_passphrase);
        self.clearAndFreeOptional(&self.auto_pty_term);
        self.clearAndFreeOptional(&self.auto_exec_command);
        self.clearAndFreeOptional(&self.kbd_interactive_response);
        self.clearAndFreeOptional(&self.client_version);
        self.clearAndFreeOptional(&self.server_version);
        self.clearAndFreeOptional(&self.pending_server_kexinit);
        self.clearPendingKeys();
        if (self.hostkey_ks) |ks| {
            std.crypto.secureZero(u8, ks);
            self.allocator.free(ks);
            self.hostkey_ks = null;
        }
        self.clearKexState();
        std.crypto.secureZero(u8, &self.session_id);
        self.session_id_established = false;
        self.user_authenticated = false;
        if (self.private_key) |*key| {
            key.clear();
            self.private_key = null;
        }
        self.channel_table.secureZeroAll();
        self.clearAllExitResults();
        self.keydata.clear();
    }

    fn clearAndFreeOptional(self: *Self, field: *?[]u8) void {
        if (field.*) |slice| {
            std.crypto.secureZero(u8, slice);
            self.allocator.free(slice);
            field.* = null;
        }
    }

    fn clearOwnedExitResult(self: *Self, result: *OwnedExitResult) void {
        switch (result.*) {
            .Signal => |signal| {
                self.allocator.free(signal.signal_name);
                self.allocator.free(signal.error_message);
                self.allocator.free(signal.language_tag);
            },
            .Status, .NoResult => {},
        }
        result.* = .NoResult;
    }

    fn clearAllExitResults(self: *Self) void {
        for (&self.exit_results) |*entry| {
            if (entry.*) |*slot| {
                if (slot.result) |*result| self.clearOwnedExitResult(result);
                entry.* = null;
            }
        }
    }

    fn findExitResultSlot(self: *Self, channel_id: u32) ?*ExitResultSlot {
        for (&self.exit_results) |*entry| {
            if (entry.*) |*slot| {
                if (slot.channel_id == channel_id) return slot;
            }
        }
        return null;
    }

    fn findExitResultSlotConst(self: *const Self, channel_id: u32) ?*const ExitResultSlot {
        for (&self.exit_results) |*entry| {
            if (entry.*) |*slot| {
                if (slot.channel_id == channel_id) return slot;
            }
        }
        return null;
    }

    fn reserveExitResult(self: *Self, channel_id: u32) SshzError!void {
        if (self.findExitResultSlot(channel_id) != null) return IoError.tooManyChannels;
        for (&self.exit_results, 0..) |*entry, index| {
            if (index >= self.limits.max_channels) break;
            if (entry.* == null) {
                entry.* = .{ .channel_id = channel_id };
                return;
            }
        }
        return IoError.tooManyChannels;
    }

    fn releaseExitResultReservation(self: *Self, channel_id: u32) void {
        for (&self.exit_results) |*entry| {
            if (entry.*) |*slot| {
                if (slot.channel_id != channel_id) continue;
                if (slot.result) |*result| self.clearOwnedExitResult(result);
                entry.* = null;
                return;
            }
        }
    }

    fn completeExitResult(self: *Self, channel_id: u32) void {
        const slot = self.findExitResultSlot(channel_id) orelse return;
        if (slot.result == null) slot.result = .NoResult;
        slot.completed = true;
    }

    pub fn automaticSessionChannelId(self: *const Self) ?u32 {
        return self.automatic_session_channel_id;
    }

    pub fn channelExitResult(self: *const Self, channel_id: u32) ?Sshz.ChannelExitResult {
        const slot = self.findExitResultSlotConst(channel_id) orelse return null;
        const result = slot.result orelse return null;
        return switch (result) {
            .Status => |status| .{ .Status = status },
            .Signal => |signal| .{ .Signal = .{
                .signal_name = signal.signal_name,
                .core_dumped = signal.core_dumped,
                .error_message = signal.error_message,
                .language_tag = signal.language_tag,
            } },
            .NoResult => .NoResult,
        };
    }

    pub fn clearChannelExitResult(self: *Self, channel_id: u32) bool {
        for (&self.exit_results) |*entry| {
            if (entry.*) |*slot| {
                if (slot.channel_id != channel_id) continue;
                if (!slot.completed) return false;
                if (slot.result) |*result| self.clearOwnedExitResult(result);
                entry.* = null;
                return true;
            }
        }
        return false;
    }

    fn clearEphemeralKeyPair(self: *Self) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.ecdh_ephem_keypair));
        self.ecdh_ephem_keypair_active = false;
    }

    fn clearKexState(self: *Self) void {
        self.clearEphemeralKeyPair();
        std.crypto.secureZero(u8, &self.shared_secret_k);
        self.kex_hasher.clear();
    }

    fn clearPrivateKeyInputs(self: *Self) void {
        self.clearAndFreeOptional(&self.privkey_ascii);
        self.clearAndFreeOptional(&self.privkey_passphrase);
    }

    fn clearPrivateKeyMaterial(self: *Self) void {
        self.clearPrivateKeyInputs();
        if (self.private_key) |*key| key.clear();
        self.private_key = null;
    }

    pub fn setIoSessionState(self: *Self, newState: Protocol.IoSessionState) void {
        TRACE(.Debug, "ioSessionState {s} -> {s}", .{ @tagName(self.ioSessionState), @tagName(newState) });
        self.ioSessionState = newState;
    }

    pub fn setSessionState(self: *Self, newState: SessionState) void {
        TRACE(.Debug, "sessionState {any} -> {any}", .{ self.sessionState, newState });
        self.sessionState = newState;
    }

    pub fn setPeerProtocolVersion(self: *Self, version: []const u8) SshzError!void {
        self.clearAndFreeOptional(&self.server_version);
        self.server_version = try self.allocator.dupe(u8, version);
    }

    pub fn setTryNoneAuth(self: *Self, enabled: bool) SshzError!void {
        if (self.auth_attempts_total != 0) return IoError.UnexpectedResponse;
        self.try_none_auth = enabled;
    }

    fn authMethodIndex(method: AuthMethod) usize {
        return @intFromEnum(method);
    }

    fn ensureAuthMethodAvailable(self: *const Self, method: AuthMethod) SshzError!void {
        const method_index = authMethodIndex(method);
        if (self.auth_attempts_total >= MaxAuthAttemptsTotal or
            self.auth_stage_attempts_by_method[method_index] >= MaxAuthAttemptsPerMethod)
        {
            return IoError.UnexpectedResponse;
        }
    }

    fn commitAuthRequest(
        self: *Self,
        sshz: *SshzClient,
        method: AuthMethod,
        packet: []const u8,
    ) SshzError!void {
        const method_index = authMethodIndex(method);
        self.auth_attempts_total += 1;
        self.auth_stage_attempts_by_method[method_index] += 1;
        self.current_auth_method = method;
        try sshz.requestWrite(packet, .Idle);
        self.setSessionState(.AuthMethodQueued);
    }

    fn rememberAuthFailure(
        self: *Self,
        attempted_method: AuthMethod,
        methods: []const u8,
        partial_success: bool,
    ) AuthFailureInfo {
        const failure = AuthFailureInfo.parse(
            attempted_method,
            methods,
            partial_success,
            self.auth_stage,
        );
        self.last_auth_failure = failure;
        return failure;
    }

    fn lastAuthFailure(self: *const Self) ?AuthFailureInfo {
        return self.last_auth_failure;
    }

    fn skipAuthMethod(self: *Self, method: AuthMethod) void {
        self.auth_stage_attempts_by_method[authMethodIndex(method)] = MaxAuthAttemptsPerMethod;
    }

    fn beginNextAuthStage(self: *Self) void {
        self.auth_stage += 1;
        self.auth_stage_attempts_by_method = .{0} ** 4;
    }

    fn resetKexHasherForRekey(self: *Self) void {
        self.clearKexState();
        self.kex_hasher = Hasher(Protocol.hash_algo).init();
        self.kex_hash_order = .Init;
        self.kex_hash_order = self.kex_hash_order.check(.V_C);
        self.kex_hasher.writeU32LenString(self.client_version.?);
        self.kex_hash_order = self.kex_hash_order.check(.V_S);
        self.kex_hasher.writeU32LenString(self.server_version.?);
    }

    pub fn startLocalRekey(self: *Self) void {
        std.debug.assert(self.encrypted and self.inbound_encrypted);
        std.debug.assert(!self.is_rekeying);
        self.resetKexHasherForRekey();
        self.clearAndFreeOptional(&self.pending_server_kexinit);
        self.rekey_resume_state = self.sessionState;
        self.is_rekeying = true;
        self.setSessionState(.KexInitWrite);
        self.setIoSessionState(.Idle);
    }

    fn startPeerRekey(self: *Self, server_kexinit: []const u8) SshzError!void {
        if (self.is_rekeying) return IoError.UnexpectedResponse;
        self.resetKexHasherForRekey();
        self.clearAndFreeOptional(&self.pending_server_kexinit);
        self.pending_server_kexinit = try self.allocator.dupe(u8, server_kexinit);
        self.rekey_resume_state = self.sessionState;
        self.is_rekeying = true;
    }

    /// Connection-protocol handlers finish by returning the session to
    /// `.ChannelActive`. RFC 4253 §9 lets those packets keep arriving while a
    /// locally-initiated re-key has parked `sessionState` in the key-exchange
    /// states, and overwriting it there would strand the re-key: the peer's
    /// KEXINIT would then look peer-initiated and be rejected. Record the
    /// target as the post-NEWKEYS resume state instead.
    fn resumeChannelActive(self: *Self) void {
        if (self.is_rekeying) {
            self.rekey_resume_state = .ChannelActive;
            return;
        }
        self.setSessionState(.ChannelActive);
    }

    fn clearPendingKeys(self: *Self) void {
        if (self.pending_c2s_keys) |*keys| keys.clear();
        if (self.pending_s2c_keys) |*keys| keys.clear();
        self.pending_c2s_keys = null;
        self.pending_s2c_keys = null;
    }

    fn decodeValidatedPrivateKey(key_data: []const u8, passphrase: ?[]const u8) SshzError!Key.PrivateKey {
        var key = try decodeOpenSshPrivateKey(key_data, passphrase);
        errdefer key.clear();
        try key.validate();
        return key;
    }

    fn bindVerifiedHostKey(self: *Self, server_hostkey: []const u8) SshzError!void {
        if (self.is_rekeying) {
            const trusted_hostkey = self.hostkey_ks orelse return IoError.HostKeyChanged;
            if (!std.mem.eql(u8, trusted_hostkey, server_hostkey)) return IoError.HostKeyChanged;
            return;
        }
        if (self.hostkey_ks != null) return IoError.UnexpectedResponse;
        self.hostkey_ks = try self.allocator.dupe(u8, server_hostkey);
    }

    fn installExchangeKeys(self: *Self, kexhash: [Protocol.hash_algo.digest_length]u8) SshzError!void {
        defer std.crypto.secureZero(u8, &self.shared_secret_k);
        if (!self.is_rekeying) {
            @memcpy(&self.session_id, &kexhash);
            self.session_id_established = true;
        } else if (!self.session_id_established) {
            // A re-key can never be the first exchange. Refuse rather than derive
            // keys against an all-zero session_id.
            return IoError.UnexpectedResponse;
        }
        self.clearPendingKeys();
        var pending = Protocol.KeyDataBi.init();
        defer pending.clear();
        try pending.genKeys(kexhash, self.shared_secret_k, self.session_id);
        pending.c2s.compression.queueAlgorithm(self.negotiated_compression_c2s);
        pending.s2c.compression.queueAlgorithm(self.negotiated_compression_s2c);
        self.pending_c2s_keys = pending.c2s;
        self.pending_s2c_keys = pending.s2c;
        pending.c2s = .{ .seq = 0 };
        pending.s2c = .{ .seq = 0 };
    }

    fn activatePendingC2sKeys(self: *Self, sshz: *SshzClient) SshzError!void {
        var next = self.pending_c2s_keys orelse return IoError.UnexpectedResponse;
        self.pending_c2s_keys = null;
        errdefer next.clear();
        next.seq = self.keydata.c2s.seq;
        try next.activateEpoch(self.keydata.c2s.epoch, sshz.keyActivationTime());
        next.compression.applyPendingAlgorithm();
        self.keydata.c2s.clear();
        self.keydata.c2s = next;
        next.clear();
        if (self.is_rekeying) try self.keydata.c2s.compression.activateDeflate();
        self.encrypted = true;
    }

    fn activatePendingS2cKeys(self: *Self, sshz: *SshzClient) SshzError!void {
        var next = self.pending_s2c_keys orelse return IoError.UnexpectedResponse;
        self.pending_s2c_keys = null;
        errdefer next.clear();
        next.seq = self.keydata.s2c.seq;
        try next.activateEpoch(self.keydata.s2c.epoch, sshz.keyActivationTime());
        next.compression.applyPendingAlgorithm();
        self.keydata.s2c.clear();
        self.keydata.s2c = next;
        next.clear();
        if (self.is_rekeying) try self.keydata.s2c.compression.activateInflate();
        self.inbound_encrypted = true;
    }

    fn preparePasswordAuth(self: *Self, sshz: *SshzClient) void {
        if (self.auth_passphrase == null) {
            self.setSessionState(.PasswordAuthStart);
            sshz.requestEvent(.GetAuthPassphrase, .Idle);
        } else {
            self.setSessionState(.PasswordAuthStart);
        }
    }

    fn continueAuthentication(
        self: *Self,
        sshz: *SshzClient,
        failure: AuthFailureInfo,
    ) SshzError!void {
        if (self.auth_attempts_total >= MaxAuthAttemptsTotal) {
            sshz.requestEvent(.{ .EndSession = .{ .AuthFailure = failure } }, .Idle);
            return;
        }

        const methods = [_]AuthMethod{
            .PublicKey,
            .Password,
            .KeyboardInteractive,
        };
        for (methods) |method| {
            const method_index = authMethodIndex(method);
            if (self.auth_stage_attempts_by_method[method_index] >= MaxAuthAttemptsPerMethod) continue;
            if (!failure.hasMethod(method)) continue;

            switch (method) {
                .PublicKey => {
                    if (self.privkey_ascii == null) {
                        self.setSessionState(.GetPrivateKeyCompleted);
                        sshz.requestEvent(.GetPrivateKey, .Idle);
                    } else {
                        self.setSessionState(.PubkeyAuthDecodeKeyPasswordless);
                    }
                },
                .Password => self.preparePasswordAuth(sshz),
                .KeyboardInteractive => self.setSessionState(.KeyboardInteractiveAuthStart),
                .None => unreachable,
            }
            return;
        }

        sshz.requestEvent(.{ .EndSession = .{ .AuthFailure = failure } }, .Idle);
    }

    fn allocateClientChannel(
        self: *Self,
        mode: ClientChannelOpenMode,
        channel_type: ChannelType,
        tcpip_open: TcpipOpen,
    ) SshzError!*Channel {
        if (mode == .AutoShell and channel_type != .Session) return IoError.UnexpectedResponse;
        const chan = self.channel_table.allocOutboundChannel() orelse return IoError.tooManyChannels;
        chan.client_open_mode = mode;
        chan.channel_type = channel_type;
        chan.tcpip_open = tcpip_open;
        chan.automatic_read_credit = self.auto_channel_read_credit_enabled;
        chan.state = .OpenWrite;
        return chan;
    }

    fn allocateClientSessionChannel(self: *Self, mode: ClientChannelOpenMode) SshzError!*Channel {
        const chan = try self.allocateClientChannel(mode, .Session, .{});
        self.reserveExitResult(chan.local_id) catch |err| {
            self.channel_table.freeChannel(chan.local_id);
            return err;
        };
        return chan;
    }

    fn activateDelayedCompression(self: *Self) SshzError!void {
        try self.keydata.c2s.compression.activateDeflate();
        try self.keydata.s2c.compression.activateInflate();
    }

    pub fn advanceSession(self: *Self, sshz: *SshzClient) SshzError!void {
        const outkeys = &self.keydata.c2s;

        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitWrite);
            },
            .KexInitWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
                var cookie: [16]u8 = undefined;
                self.rand.bytes(&cookie);
                try pkt.writeBytes(&cookie);

                const offers = Protocol.localAlgorithmOffers(Key.client_hostkey_algorithms);
                try pkt.writeU32LenString(offers.kex);
                try pkt.writeU32LenString(offers.host_key);
                try pkt.writeU32LenString(offers.encryption_c2s);
                try pkt.writeU32LenString(offers.encryption_s2c);
                try pkt.writeU32LenString(offers.mac_c2s);
                try pkt.writeU32LenString(offers.mac_s2c);
                try pkt.writeU32LenString(offers.compression_c2s);
                try pkt.writeU32LenString(offers.compression_s2c);
                try pkt.writeU32LenString(""); // lang c2s
                try pkt.writeU32LenString(""); // lang s2c

                const first_kex_packet_follows = false;
                try pkt.writeBoolean(first_kex_packet_follows);
                try pkt.writeU32(0); // reserved

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(pkt.active());

                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
                if (self.pending_server_kexinit) |server_kexinit| {
                    self.kex_hash_order = self.kex_hash_order.check(.I_S);
                    self.kex_hasher.writeU32LenString(server_kexinit);
                    self.clearAndFreeOptional(&self.pending_server_kexinit);
                    self.setSessionState(.EcdhInitWrite);
                } else {
                    self.setSessionState(.KexInitRead);
                }
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhInitWrite => {
                errdefer self.clearKexState();
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT));

                var seed: [Protocol.kex_algo.seed_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &seed);
                self.rand.bytes(&seed);
                self.clearEphemeralKeyPair();
                self.ecdh_ephem_keypair = Protocol.kex_algo.KeyPair.generateDeterministic(seed) catch unreachable;
                self.ecdh_ephem_keypair_active = true;
                var q_c = self.ecdh_ephem_keypair.public_key;
                try pkt.writeU32LenString(&q_c);

                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
                self.setSessionState(.EcdhReply);
            },
            .EcdhReply => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .CheckHostKey => {
                if (self.is_rekeying) {
                    // bindVerifiedHostKey already matched this key to the accepted identity.
                    self.setSessionState(.NewKeysRead);
                    self.setIoSessionState(.ReadPktHdr);
                } else {
                    sshz.requestEvent(.{ .CheckHostKey = .{
                        .raw_key = self.hostkey_ks,
                        .fingerprint = blk: {
                            var fp: [Protocol.hash_algo.digest_length]u8 = undefined;
                            if (self.hostkey_ks) |ks| {
                                Protocol.hash_algo.hash(ks, &fp, .{});
                            } else {
                                @memset(&fp, 0);
                            }
                            break :blk fp;
                        },
                    } }, .Idle);
                    self.setSessionState(.HostKeyDecision);
                }
            },
            .HostKeyDecision, .HostKeyRejected => {},
            .NewKeysRead => {
                //std.debug.assert(false);
                // FIXME explain why empty
            },
            .NewKeysWrite => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr);
                try sshz.requestWrite(wrapped, .Idle);
                try self.activatePendingC2sKeys(sshz);
                if (self.is_rekeying) {
                    const resume_state = self.rekey_resume_state orelse .ChannelActive;
                    self.is_rekeying = false;
                    self.rekey_resume_state = null;
                    self.setSessionState(resume_state);
                } else {
                    self.setSessionState(.AuthServReq);
                }
            },
            .AuthServReq => {
                // https://datatracker.ietf.org/doc/html/rfc4253
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_REQUEST));
                try pkt.writeU32LenString("ssh-userauth");
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
                self.setSessionState(.AuthServRsp);
            },
            .AuthServRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthStart => {
                if (self.try_none_auth) {
                    self.setSessionState(.NoneAuthReq);
                } else if (self.privkey_ascii == null) {
                    sshz.requestEvent(.GetPrivateKey, .Idle);
                    self.setSessionState(.GetPrivateKeyCompleted);
                } else {
                    self.setSessionState(.PubkeyAuthDecodeKeyPasswordless);
                }
            },
            .NoneAuthReq => {
                try self.ensureAuthMethodAvailable(.None);
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("none");
                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr);
                try self.commitAuthRequest(sshz, .None, wrapped);
            },
            .GetPrivateKeyCompleted => {
                if (self.privkey_ascii != null) {
                    self.setSessionState(.PubkeyAuthDecodeKeyPasswordless);
                } else if (self.lastAuthFailure()) |failure| {
                    self.skipAuthMethod(.PublicKey);
                    try self.continueAuthentication(sshz, failure);
                } else {
                    self.preparePasswordAuth(sshz);
                }
            },
            .PubkeyAuthDecodeKeyPasswordless => {
                if (self.privkey_ascii) |privkey_ascii| { // have private key
                    errdefer self.clearPrivateKeyInputs();
                    // attempt passwordless
                    if (self.private_key) |*old| {
                        old.clear();
                        self.private_key = null;
                    }
                    self.private_key = decodeValidatedPrivateKey(privkey_ascii, null) catch |err| {
                        switch (err) {
                            PrivKeyError.InvalidKeyDecrypt => {
                                // need a passphrase to decode key
                                sshz.requestEvent(.GetKeyPassphrase, .Idle);
                                self.setSessionState(.PubkeyAuthDecodeKeyPassword);
                                return;
                            },
                            else => {
                                return err;
                            },
                        }
                    };
                    self.clearPrivateKeyInputs();
                    // key decoded ok, so must have been passwordless
                    self.setSessionState(.PubkeyAuthStart);
                } else {
                    // no key available
                    // try password auth
                    self.preparePasswordAuth(sshz);
                }
            },
            .PubkeyAuthStart => {
                self.setSessionState(.PubkeyAuthReq);
            },
            .PubkeyAuthReq => {
                defer self.clearPrivateKeyMaterial();
                try self.ensureAuthMethodAvailable(.PublicKey);
                // https://datatracker.ietf.org/doc/html/rfc4252#section-7
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8

                const private_key = if (self.private_key) |*key| key else return IoError.UnexpectedResponse;
                const sig_alg = private_key.defaultSignatureAlgorithm();

                var pubkey_blob: Key.Blob = .{};
                const typed_pubkey = try private_key.publicBlob(&pubkey_blob);

                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("publickey");
                try pkt.writeBoolean(true);
                try pkt.writeU32LenString(sig_alg.name());
                try pkt.writeU32LenString(typed_pubkey);

                var backing_sigbuffer_buf: [1024]u8 = undefined;
                defer std.crypto.secureZero(u8, &backing_sigbuffer_buf);
                var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                try sigbuffer.writeU32LenString(&self.session_id);
                try sigbuffer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                try sigbuffer.writeU32LenString(self.username);
                try sigbuffer.writeU32LenString("ssh-connection");
                try sigbuffer.writeU32LenString("publickey");
                try sigbuffer.writeBoolean(true);
                try sigbuffer.writeU32LenString(sig_alg.name());
                try sigbuffer.writeU32LenString(typed_pubkey);

                var typed_sig: Key.SignatureBlob = .{};
                defer typed_sig.clear();
                const sig = try private_key.sign(sig_alg, sigbuffer.active(), &typed_sig);
                UNSAFE_TRACEDUMP(.Debug, "sigbytes", .{}, sig);
                try pkt.writeU32LenString(sig);

                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr);
                try self.commitAuthRequest(sshz, .PublicKey, wrapped);
            },
            .PubkeyAuthDecodeKeyPassword => {
                // attempt decode with passphrase
                // if this fails, drop to password auth
                if (self.private_key) |*old| {
                    old.clear();
                    self.private_key = null;
                }
                self.private_key = decodeValidatedPrivateKey(self.privkey_ascii.?, self.privkey_passphrase) catch |err| {
                    self.clearPrivateKeyInputs();
                    switch (err) {
                        PrivKeyError.InvalidKeyDecrypt => {
                            self.skipAuthMethod(.PublicKey);
                            if (self.lastAuthFailure()) |failure| {
                                try self.continueAuthentication(sshz, failure);
                            } else {
                                self.preparePasswordAuth(sshz);
                            }
                            return;
                        },
                        else => return err,
                    }
                };
                self.clearPrivateKeyInputs();
                // key decode ok, continue with pubkey
                self.setSessionState(.PubkeyAuthStart);
            },
            .PasswordAuthStart => {
                if (self.auth_passphrase == null) return IoError.UnexpectedResponse;
                self.setSessionState(.PasswordAuthReq);
            },
            .PasswordAuthReq => {
                defer self.clearAndFreeOptional(&self.auth_passphrase);
                try self.ensureAuthMethodAvailable(.Password);
                std.debug.assert(self.auth_passphrase != null);
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("password");
                try pkt.writeBoolean(false);
                try pkt.writeU32LenString(self.auth_passphrase.?);
                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr);
                try self.commitAuthRequest(sshz, .Password, wrapped);
            },
            .KeyboardInteractiveAuthStart => {
                self.setSessionState(.KeyboardInteractiveAuthReq);
            },
            .KeyboardInteractiveAuthReq => {
                try self.ensureAuthMethodAvailable(.KeyboardInteractive);
                // RFC 4256 §3.1 - send keyboard-interactive auth request
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("keyboard-interactive");
                try pkt.writeU32LenString(""); // language tag
                try pkt.writeU32LenString(""); // submethods
                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr);
                try self.commitAuthRequest(sshz, .KeyboardInteractive, wrapped);
            },
            .KeyboardInteractiveInfoRsp => {
                defer self.clearAndFreeOptional(&self.kbd_interactive_response);
                // RFC 4256 §3.4 - send response to info request
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_INFO_RESPONSE));
                try pkt.writeU32(1); // num-responses
                if (self.kbd_interactive_response) |resp| {
                    try pkt.writeU32LenString(resp);
                } else {
                    try pkt.writeU32LenString("");
                }
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .AuthMethodQueued => {
                const method = self.current_auth_method orelse return IoError.UnexpectedResponse;
                self.setSessionState(.AuthRsp);
                sshz.requestEvent(.{ .AuthMethodStarted = method }, .Idle);
            },
            .AuthRsp => { // for password or pubkey
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelOpenReq => {
                if (!self.auto_session_enabled) {
                    self.setSessionState(.ChannelActive);
                    sshz.requestEvent(.Connected, .Idle);
                    return;
                }
                const mode: ClientChannelOpenMode = if (self.auto_exec_command != null) .AutoExec else .AutoShell;
                const chan = try self.allocateClientSessionChannel(mode);
                self.automatic_session_channel_id = chan.local_id;
                self.active_channel_id = chan.local_id;
                self.setSessionState(.ChannelActive);
            },
            .ChannelOpenRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelActive => {
                if (try self.flushPendingChannelReply(sshz)) return;
                if (try self.flushPendingKeepalive(sshz)) return;
                try self.advanceChannel(sshz, outkeys);
            },
        }
    }

    fn advanceChannel(self: *Self, sshz: *SshzClient, outkeys: *Protocol.KeyDataUni) SshzError!void {
        const ch = if (self.active_channel_id) |id|
            self.channel_table.findByLocalId(id)
        else
            self.channel_table.findNextRunnable();

        if (ch == null) {
            self.setIoSessionState(.ReadPktHdr);
            return;
        }

        const chan = ch.?;
        self.active_channel_id = chan.local_id;

        if (chan.remote_id_known and (chan.state == .Data or chan.state == .DataRx) and
            !chan.eof_received and !chan.close_pending and !chan.close_sent and !chan.close_received and
            chan.needsWindowAdjust())
        {
            _ = try self.startChannelWindowAdjust(chan, sshz, outkeys);
            chan.state = .DataRx;
            self.active_channel_id = null;
            if (self.channel_table.findNextRunnable() == null) self.setIoSessionState(.ReadPktHdr);
            return;
        }

        if ((chan.close_received or chan.close_pending) and chan.write_buf_nbytes > 0 and chan.tx_in_flight_len == 0) {
            chan.discardWriteBuffer();
            chan.eof_pending = false;
        }
        const can_send_data = switch (chan.state) {
            .Data, .DataRx, .DataTx, .DataTxComplete => true,
            else => false,
        };
        if (can_send_data and !chan.eof_sent and !chan.close_sent and !chan.close_pending and !chan.close_received and
            chan.write_buf_nbytes > 0 and chan.tx_in_flight_len == 0 and chan.peer_window > 0)
        {
            _ = try self.startChannelWrite(chan, sshz, outkeys);
            return;
        }
        if (chan.write_buf_nbytes == 0 and chan.tx_in_flight_len == 0 and chan.control_in_flight == null) {
            if (try self.startPendingChannelControl(chan, sshz, outkeys)) return;
        }

        switch (chan.state) {
            .OpenWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                try pkt.writeU32LenString(chan.channel_type.name()); // https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.1
                try pkt.writeU32(chan.local_id); // sender channel
                try pkt.writeU32(self.limits.initial_channel_window);
                try pkt.writeU32(self.limits.channel_packet_size);
                if (chan.channel_type.hasTcpipOpenPayload()) {
                    try pkt.writeU32LenString(chan.tcpip_open.host);
                    try pkt.writeU32(chan.tcpip_open.port);
                    try pkt.writeU32LenString(chan.tcpip_open.originator_host);
                    try pkt.writeU32(chan.tcpip_open.originator_port);
                }
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
                self.setSessionState(.ChannelOpenRsp);
            },
            .Open => {
                if (chan.kind != .Session) {
                    chan.state = .Data;
                    return;
                }
                const request_pty = chan.client_open_mode == .AutoShell or
                    (chan.client_open_mode == .AutoExec and self.auto_pty_requested);
                if (!request_pty) {
                    chan.state = .RspWrite;
                    try self.advanceChannel(sshz, outkeys);
                    return;
                }
                defer {
                    self.clearAndFreeOptional(&self.auto_pty_term);
                    self.auto_pty_requested = false;
                }
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32LenString("pty-req");
                try pkt.writeBoolean(false); // want reply
                try pkt.writeU32LenString(self.auto_pty_term orelse "xterm-color");
                try pkt.writeU32(self.auto_pty_cols);
                try pkt.writeU32(self.auto_pty_rows);
                try pkt.writeU32(self.auto_pty_width_px);
                try pkt.writeU32(self.auto_pty_height_px);

                // magic pulled from observing OpenSSH connect
                const termdata = &[_]u8{
                    0x81, 0x00, 0x00, 0x25, 0x80, 0x80, 0x00,
                    0x00, 0x25, 0x80, 0x01, 0x00, 0x00, 0x00,
                    0x03, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x03,
                    0x00, 0x00, 0x00, 0x7f, 0x04, 0x00, 0x00,
                    0x00, 0x15, 0x05, 0x00, 0x00, 0x00, 0x04,
                    0x06, 0x00, 0x00, 0x00, 0xff, 0x07, 0x00,
                    0x00, 0x00, 0xff, 0x08, 0x00, 0x00, 0x00,
                    0x11, 0x09, 0x00, 0x00, 0x00, 0x13, 0x0a,
                    0x00, 0x00, 0x00, 0x1a, 0x0b, 0x00, 0x00,
                    0x00, 0x19, 0x0c, 0x00, 0x00, 0x00, 0x12,
                    0x0d, 0x00, 0x00, 0x00, 0x17, 0x0e, 0x00,
                    0x00, 0x00, 0x16, 0x11, 0x00, 0x00, 0x00,
                    0x14, 0x12, 0x00, 0x00, 0x00, 0x0f, 0x1e,
                    0x00, 0x00, 0x00, 0x01, 0x1f, 0x00, 0x00,
                    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
                    0x21, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                    0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
                    0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x26,
                    0x00, 0x00, 0x00, 0x01, 0x27, 0x00, 0x00,
                    0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                    0x29, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x00,
                    0x00, 0x00, 0x01, 0x32, 0x00, 0x00, 0x00,
                    0x01, 0x33, 0x00, 0x00, 0x00, 0x01, 0x35,
                    0x00, 0x00, 0x00, 0x01, 0x36, 0x00, 0x00,
                    0x00, 0x01, 0x37, 0x00, 0x00, 0x00, 0x01,
                    0x38, 0x00, 0x00, 0x00, 0x00, 0x39, 0x00,
                    0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00,
                    0x00, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x3c,
                    0x00, 0x00, 0x00, 0x01, 0x3d, 0x00, 0x00,
                    0x00, 0x01, 0x3e, 0x00, 0x00, 0x00, 0x01,
                    0x46, 0x00, 0x00, 0x00, 0x01, 0x48, 0x00,
                    0x00, 0x00, 0x01, 0x49, 0x00, 0x00, 0x00,
                    0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x4b,
                    0x00, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00,
                    0x00, 0x01, 0x5b, 0x00, 0x00, 0x00, 0x01,
                    0x5c, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                };
                try pkt.writeU32LenString(termdata);

                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
                chan.state = .RspWrite;
            },
            .RspWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                try pkt.writeU32(chan.remote_id);
                if (self.agent_forwarding_enabled and !self.agent_forwarding_requested) {
                    try pkt.writeU32LenString(Protocol.channel_request_auth_agent);
                    try pkt.writeBoolean(false); // want reply
                    self.agent_forwarding_requested = true;
                } else {
                    switch (chan.client_open_mode) {
                        .AutoShell => {
                            try pkt.writeU32LenString("shell");
                            try pkt.writeBoolean(false); // want reply
                        },
                        .AutoExec => {
                            const command = self.auto_exec_command orelse return IoError.UnexpectedResponse;
                            defer self.clearAndFreeOptional(&self.auto_exec_command);
                            try pkt.writeU32LenString("exec");
                            try pkt.writeBoolean(false); // want reply
                            try pkt.writeU32LenString(command);
                        },
                        .RawSession => return IoError.UnexpectedResponse,
                    }
                    chan.state = .Connected;
                }

                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .RspFailureWrite => return IoError.UnexpectedResponse,
            .Connected => {
                switch (chan.kind) {
                    .Session => sshz.requestEvent(.Connected, .Idle),
                    .AgentForward => sshz.requestEvent(.{ .AgentChannelOpen = chan.local_id }, .Idle),
                }
                chan.state = .Data;
            },
            .Data => {
                chan.state = .DataRx;
                self.active_channel_id = null;
                if (self.channel_table.findNextRunnable()) |_| {} else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .DataRx => {
                self.active_channel_id = null;
                if (self.channel_table.findNextRunnable()) |next| {
                    self.active_channel_id = next.local_id;
                    try self.advanceChannel(sshz, outkeys);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .DataTx => {
                chan.state = .Data;
            },
            .DataTxComplete => {
                chan.state = .Data;
            },
            .EofWrite => {
                chan.eof_pending = true;
                chan.state = .DataRx;
                _ = try self.startPendingChannelControl(chan, sshz, outkeys);
            },
            .CloseWrite => {
                chan.close_pending = true;
                chan.state = .DataRx;
                _ = try self.startPendingChannelControl(chan, sshz, outkeys);
            },
            .Closed => {
                const local_id = chan.local_id;
                const kind = chan.kind;
                if (kind == .Session and chan.channel_type == .Session) {
                    self.completeExitResult(local_id);
                }
                self.active_channel_id = null;
                if (kind == .AgentForward) {
                    self.channel_table.freeChannel(local_id);
                    sshz.requestEvent(.{ .AgentChannelClosed = local_id }, .Idle);
                } else {
                    sshz.requestEvent(.{ .ChannelClosed = local_id }, .Idle);
                }
            },
            .ConfirmWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(chan.local_id);
                try pkt.writeU32(self.limits.initial_channel_window);
                try pkt.writeU32(self.limits.channel_packet_size);
                chan.state = if (chan.kind == .AgentForward or chan.channel_type == .Session) .Connected else .Data;
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .OpenFailureWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(chan.open_failure_reason_code);
                try pkt.writeU32LenString(chan.open_failure_description);
                try pkt.writeU32LenString("");
                const local_id = chan.local_id;
                self.channel_table.freeChannel(local_id);
                self.active_channel_id = null;
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .OpenSent => {
                self.setIoSessionState(.ReadPktHdr);
            },
        }
    }

    pub fn getChannelWriteBuffer(self: *Self, channel_id: u32) SshzError![]u8 {
        if (self.channel_table.findByLocalId(channel_id)) |chan| {
            if (chan.eof_sent or chan.eof_pending or chan.close_sent or chan.close_pending or chan.close_received) return &.{};
            if (chan.write_buf_nbytes > 0) {
                return &.{};
            } else {
                return chan.write_buf[0..chan.max_buffered_data];
            }
        }
        return &.{};
    }

    pub fn openSessionChannel(self: *Self, sshz: *SshzClient) SshzError!u32 {
        if (sshz.iostate_wr != .Idle or self.active_channel_id != null) {
            return IoError.cannotAcceptWrite;
        }
        if (self.sessionState != .ChannelActive) {
            return IoError.NotReady;
        }

        const chan = try self.allocateClientSessionChannel(.RawSession);
        self.active_channel_id = chan.local_id;
        self.setIoSessionState(.Idle);
        try self.advanceChannel(sshz, &self.keydata.c2s);
        return chan.local_id;
    }

    pub fn openDirectTcpipChannel(
        self: *Self,
        sshz: *SshzClient,
        host: []const u8,
        port: u32,
        originator_host: []const u8,
        originator_port: u32,
    ) SshzError!u32 {
        if (sshz.iostate_wr != .Idle or self.active_channel_id != null) {
            return IoError.cannotAcceptWrite;
        }
        if (self.sessionState != .ChannelActive) {
            return IoError.NotReady;
        }

        const chan = try self.allocateClientChannel(.RawSession, .DirectTcpip, .{
            .host = host,
            .port = port,
            .originator_host = originator_host,
            .originator_port = originator_port,
        });
        self.active_channel_id = chan.local_id;
        self.setIoSessionState(.Idle);
        try self.advanceChannel(sshz, &self.keydata.c2s);
        return chan.local_id;
    }

    pub fn openLocalForwardChannel(
        self: *Self,
        sshz: *SshzClient,
        host: []const u8,
        port: u32,
        originator_host: []const u8,
        originator_port: u32,
    ) SshzError!u32 {
        return try self.openDirectTcpipChannel(sshz, host, port, originator_host, originator_port);
    }

    fn sendTcpipForwardGlobalRequest(
        self: *Self,
        sshz: *SshzClient,
        kind: PendingGlobalRequestKind,
        bind_address: []const u8,
        bind_port: u32,
    ) SshzError!void {
        if (self.global_requests_ended or sshz.terminated) return IoError.SessionTerminated;
        if (self.pending_global_request != null) return IoError.ResourceLimitExceeded;
        if (sshz.iostate_wr != .Idle or self.active_channel_id != null) {
            return IoError.cannotAcceptWrite;
        }
        if (self.sessionState != .ChannelActive) {
            return IoError.NotReady;
        }
        if (bind_address.len > self.pending_global_request_bind_address.len) {
            return IoError.tooBig;
        }

        @memcpy(self.pending_global_request_bind_address[0..bind_address.len], bind_address);
        const stored_bind_address = self.pending_global_request_bind_address[0..bind_address.len];

        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST));
        try pkt.writeU32LenString(switch (kind) {
            .TcpipForward => "tcpip-forward",
            .CancelTcpipForward => "cancel-tcpip-forward",
            .Keepalive => unreachable,
        });
        try pkt.writeBoolean(true); // want reply
        try pkt.writeU32LenString(stored_bind_address);
        try pkt.writeU32(bind_port);

        const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.c2s, &pkt, &sshz.iobuf_wr);
        self.pending_global_request = .{
            .kind = kind,
            .bind_address = stored_bind_address,
            .bind_port = bind_port,
        };
        try sshz.requestWrite(wrapped, .GlobalRequestWriteComplete);
    }

    pub fn queueKeepalive(self: *Self) SshzError!Sshz.KeepaliveToken {
        if (self.global_requests_ended) return IoError.SessionTerminated;
        if (!self.user_authenticated) return IoError.NotReady;
        if (self.pending_global_request != null or self.keepalive != null)
            return IoError.ResourceLimitExceeded;
        if (self.last_keepalive_id == std.math.maxInt(u64)) return IoError.ResourceLimitExceeded;
        self.last_keepalive_id += 1;
        const token = Sshz.KeepaliveToken{ .id = self.last_keepalive_id };
        self.keepalive = .{ .token = token };
        self.pending_global_request = .{ .kind = .Keepalive, .transmission = .Queued };
        return token;
    }

    pub fn keepaliveStatus(self: *const Self, token: Sshz.KeepaliveToken) SshzError!Sshz.KeepaliveStatus {
        const status = self.keepalive orelse return IoError.InvalidKeepaliveToken;
        if (status.token.id != token.id) return IoError.InvalidKeepaliveToken;
        return status;
    }

    pub fn markKeepaliveFlushed(self: *Self, token: Sshz.KeepaliveToken) SshzError!void {
        const status = try self.keepaliveStatus(token);
        if (status.transmission != .HandedToTransport) return IoError.NotReady;
        if (status.outcome == .Disconnected) return IoError.SessionTerminated;
        self.keepalive.?.transport_flushed = true;
    }

    pub fn cancelKeepalive(self: *Self, token: Sshz.KeepaliveToken) SshzError!void {
        const status = try self.keepaliveStatus(token);
        if (status.outcome != .Pending) return;
        self.keepalive.?.outcome = .Cancelled;
        // Once framed, even zero consumed bytes cannot safely be retracted:
        // encryption sequence numbers and compression have already advanced.
        if (status.transmission == .Queued) self.pending_global_request = null;
    }

    pub fn clearKeepalive(self: *Self, token: Sshz.KeepaliveToken) SshzError!void {
        if ((try self.keepaliveStatus(token)).outcome == .Pending) return IoError.NotReady;
        self.keepalive = null;
    }

    pub fn endGlobalRequests(self: *Self) void {
        self.global_requests_ended = true;
        self.pending_global_request = null;
        if (self.keepalive) |*status| {
            if (status.outcome == .Pending) status.outcome = .Disconnected;
        }
    }

    pub fn flushPendingKeepalive(self: *Self, sshz: *SshzClient) SshzError!bool {
        const pending = self.pending_global_request orelse return false;
        if (pending.kind != .Keepalive or pending.transmission != .Queued or
            self.global_requests_ended or self.sessionState != .ChannelActive or
            self.is_rekeying or sshz.local_rekey_pending or sshz.iostate_wr != .Idle)
            return false;
        // Process a fully received packet before initiating another request.
        // Incomplete reads remain intact while the independent write runs.
        switch (self.ioSessionState) {
            .Idle, .ReadPktHdr, .ReadPktBody => {},
            else => return false,
        }
        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST));
        try pkt.writeU32LenString("keepalive@openssh.com");
        try pkt.writeBoolean(true);
        try sshz.requestWrite(
            try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.c2s, &pkt, &sshz.iobuf_wr),
            .GlobalRequestWriteComplete,
        );
        self.pending_global_request.?.transmission = .Emitting;
        self.keepalive.?.transmission = .Emitting;
        return true;
    }

    pub fn completeGlobalRequestWrite(self: *Self, sshz: *SshzClient) SshzError!void {
        const pending = if (self.pending_global_request) |*request|
            request
        else
            return IoError.UnexpectedResponse;
        if (pending.transmission != .Emitting) return IoError.UnexpectedResponse;
        pending.transmission = .HandedToTransport;
        if (pending.kind == .Keepalive) {
            if (self.keepalive) |*status| status.transmission = .HandedToTransport;
        }
        const received_packet_pending = switch (self.ioSessionState) {
            .ReadPktCompletion => true,
            else => false,
        };
        if (!received_packet_pending) _ = try self.dispatchDeferredChannelWrite(sshz);
    }

    pub fn requestRemoteForward(self: *Self, sshz: *SshzClient, bind_address: []const u8, bind_port: u32) SshzError!void {
        try self.sendTcpipForwardGlobalRequest(sshz, .TcpipForward, bind_address, bind_port);
    }

    pub fn cancelRemoteForward(self: *Self, sshz: *SshzClient, bind_address: []const u8, bind_port: u32) SshzError!void {
        try self.sendTcpipForwardGlobalRequest(sshz, .CancelTcpipForward, bind_address, bind_port);
    }

    pub fn acceptChannelOpen(self: *Self, channel_id: u32) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.state != .Open) return IoError.UnexpectedResponse;
        chan.state = .ConfirmWrite;
        self.active_channel_id = channel_id;
        self.resumeChannelActive();
        self.setIoSessionState(.Idle);
    }

    pub fn acceptHostKey(self: *Self) SshzError!void {
        if (self.sessionState != .HostKeyDecision) return IoError.UnexpectedResponse;
        self.setSessionState(.NewKeysRead);
        self.setIoSessionState(.ReadPktHdr);
    }

    pub fn rejectHostKey(self: *Self, sshz: *SshzClient) SshzError!void {
        if (self.sessionState != .HostKeyDecision) return IoError.UnexpectedResponse;
        var fingerprint: [Protocol.hash_algo.digest_length]u8 = .{0} ** Protocol.hash_algo.digest_length;
        if (self.hostkey_ks) |hostkey| Protocol.hash_algo.hash(hostkey, &fingerprint, .{});
        self.setSessionState(.HostKeyRejected);
        self.setIoSessionState(.Idle);
        sshz.requestEvent(.{ .EndSession = .{ .HostKeyRejected = .{
            .raw_key = self.hostkey_ks,
            .fingerprint = fingerprint,
        } } }, .Idle);
    }

    pub fn rejectChannelOpen(self: *Self, channel_id: u32, reason_code: u32, description: []const u8) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.state != .Open) return IoError.UnexpectedResponse;
        chan.open_failure_reason_code = reason_code;
        chan.open_failure_description = description;
        chan.state = .OpenFailureWrite;
        self.active_channel_id = channel_id;
        self.resumeChannelActive();
        self.setIoSessionState(.Idle);
    }

    pub fn channelWriteComplete(self: *Self, channel_id: u32, nbytes: usize) SshzError!void {
        const chan = try self.queueChannelWrite(channel_id, nbytes);
        if (chan.state == .DataRx) {
            self.resumeChannelActive();
            self.setIoSessionState(.Idle);
        }
    }

    pub fn queueChannelWrite(self: *Self, channel_id: u32, nbytes: usize) SshzError!*Channel {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent or chan.eof_pending or chan.close_sent or chan.close_pending or chan.close_received) return IoError.UnexpectedResponse;
        if (nbytes > chan.max_buffered_data) {
            return IoError.tooBig;
        }
        if (nbytes > self.limits.max_pending_buffered_data -| self.pendingBufferedData())
            return IoError.ResourceLimitExceeded;
        if (chan.write_buf_nbytes != 0 or chan.tx_in_flight_len != 0) return IoError.UnexpectedResponse;
        chan.write_buf_nbytes = nbytes;
        self.active_channel_id = channel_id;
        return chan;
    }

    // Full-duplex: build and send channel data packet directly without going through state machine
    pub fn directChannelWrite(self: *Self, channel_id: u32, nbytes: usize, sshz: *SshzClient) SshzError!void {
        const chan = try self.queueChannelWrite(channel_id, nbytes);
        _ = try self.startChannelWrite(chan, sshz, &self.keydata.c2s);
    }

    fn startChannelWrite(
        self: *Self,
        chan: *Channel,
        sshz: *SshzClient,
        outkeys: *Protocol.KeyDataUni,
    ) SshzError!bool {
        if (self.sessionState != .ChannelActive or self.is_rekeying or sshz.local_rekey_pending or
            !chan.remote_id_known or chan.close_pending or
            chan.tx_in_flight_len != 0 or chan.write_buf_nbytes == 0)
        {
            return false;
        }
        const max_send = @min(chan.remote_max_packet_size, @as(u32, @intCast(chan.write_buf_nbytes)));
        const send_len = @min(max_send, chan.peer_window);
        if (send_len == 0) return false;
        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
        try pkt.writeU32(chan.remote_id);
        try pkt.writeU32LenString(chan.write_buf[0..send_len]);
        try sshz.requestWrite(
            try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr),
            .{ .ChannelWriteComplete = chan.local_id },
        );
        chan.peer_window -= @intCast(send_len);
        chan.tx_in_flight_len = send_len;
        return true;
    }

    pub fn completeChannelWrite(self: *Self, channel_id: u32, sshz: *SshzClient) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.tx_in_flight_len == 0) return IoError.UnexpectedResponse;
        chan.consumeWriteBuffer(chan.tx_in_flight_len);
        chan.tx_in_flight_len = 0;
        if (chan.close_received) {
            chan.discardWriteBuffer();
            chan.eof_pending = false;
            _ = try self.dispatchDeferredChannelWrite(sshz);
            return;
        }
        const received_packet_pending = switch (self.ioSessionState) {
            .ReadPktCompletion => true,
            else => false,
        };
        if (received_packet_pending) return;
        if (chan.close_pending) {
            chan.discardWriteBuffer();
            chan.eof_pending = false;
            const queued = try self.startPendingChannelControl(chan, sshz, &self.keydata.c2s);
            if (!queued) _ = try self.dispatchDeferredChannelWrite(sshz);
            return;
        }
        var queued = false;
        if (chan.write_buf_nbytes > 0) {
            queued = try self.startChannelWrite(chan, sshz, &self.keydata.c2s);
        } else {
            queued = try self.startPendingChannelControl(chan, sshz, &self.keydata.c2s);
        }
        if (!queued) _ = try self.dispatchDeferredChannelWrite(sshz);
    }

    /// Sends a queued `window-change` for the session channel, if one is due.
    ///
    /// The write completes back into whatever `ioSessionState` was current
    /// rather than into `.Idle`. A resize arrives on its own schedule, almost
    /// always while a read is in flight, and that read's completion state is
    /// still the one the session must return to; restoring it makes this a
    /// packet interjected into the stream rather than a step in the sequence.
    ///
    /// The request is cleared before the write so a failure cannot leave it
    /// retrying against a channel that is going away, and a resize that lands
    /// while one is in flight simply replaces it — only the latest size matters.
    fn startPendingWindowChange(
        self: *Self,
        sshz: *SshzClient,
        outkeys: *Protocol.KeyDataUni,
    ) SshzError!bool {
        if (self.pending_window_change == null) return false;

        const chan = self.channel_table.findByKind(.Session) orelse return false;
        if (!chan.remote_id_known or chan.tx_in_flight_len != 0 or
            chan.close_pending or chan.close_sent or chan.close_received)
        {
            return false;
        }

        const wc = self.pending_window_change.?;
        self.pending_window_change = null;

        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
        try pkt.writeU32(chan.remote_id);
        try pkt.writeU32LenString("window-change");
        try pkt.writeBoolean(false); // want reply
        try pkt.writeU32(wc[0]); // cols
        try pkt.writeU32(wc[1]); // rows
        try pkt.writeU32(wc[2]); // width_px
        try pkt.writeU32(wc[3]); // height_px
        try sshz.requestWrite(
            try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr),
            self.ioSessionState,
        );
        return true;
    }

    /// Flushes a queued `window-change` as soon as the write side is free.
    ///
    /// `advance` calls this ahead of the io state machine because the state
    /// machine cannot reach it: waiting for a packet parks the session in
    /// `.ReadPktHdr` with a read outstanding, which `canProcessIoSessionState`
    /// refuses to advance, so a resize on an otherwise quiet connection would
    /// sit queued until the server happened to send something. The write side
    /// is tracked separately from the read side and is free in that state, so
    /// there is nothing to wait for.
    pub fn flushPendingWindowChange(self: *Self, sshz: *SshzClient) SshzError!bool {
        if (self.pending_window_change == null) return false;
        if (self.pending_channel_replies_len != 0 or
            self.sessionState != .ChannelActive or self.is_rekeying or
            sshz.local_rekey_pending or sshz.iostate_wr != .Idle)
        {
            return false;
        }
        return try self.startPendingWindowChange(sshz, &self.keydata.c2s);
    }

    fn startPendingChannelControl(
        self: *Self,
        chan: *Channel,
        sshz: *SshzClient,
        outkeys: *Protocol.KeyDataUni,
    ) SshzError!bool {
        if (self.sessionState != .ChannelActive or self.is_rekeying or sshz.local_rekey_pending or
            !chan.remote_id_known or
            sshz.iostate_wr != .Idle or chan.write_buf_nbytes != 0 or
            chan.tx_in_flight_len != 0 or chan.control_in_flight != null)
        {
            return false;
        }
        const control: ChannelControl = if (chan.close_received and !chan.close_sent)
            .Close
        else if (chan.close_pending and !chan.close_sent)
            .Close
        else if (chan.eof_pending and !chan.eof_sent)
            .Eof
        else
            return false;

        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(switch (control) {
            .Eof => Protocol.MsgId.SSH_MSG_CHANNEL_EOF,
            .Close => Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE,
        }));
        try pkt.writeU32(chan.remote_id);
        try sshz.requestWrite(
            try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr),
            .{ .ChannelControlComplete = chan.local_id },
        );
        chan.control_in_flight = control;
        switch (control) {
            .Eof => {
                chan.eof_pending = false;
                chan.eof_sent = true;
            },
            .Close => {
                chan.close_pending = false;
                chan.close_sent = true;
                chan.eof_pending = false;
            },
        }
        return true;
    }

    fn startChannelWindowAdjust(
        self: *Self,
        chan: *Channel,
        sshz: *SshzClient,
        outkeys: *Protocol.KeyDataUni,
    ) SshzError!bool {
        if (self.sessionState != .ChannelActive or self.is_rekeying or sshz.local_rekey_pending or
            !chan.remote_id_known or sshz.iostate_wr != .Idle or
            (chan.state != .Data and chan.state != .DataRx) or
            chan.eof_received or chan.close_pending or chan.close_sent or chan.close_received or
            !chan.needsWindowAdjust())
        {
            return false;
        }

        const adjust = chan.windowAdjustAmount();
        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
        try pkt.writeU32(chan.remote_id);
        try pkt.writeU32(adjust);
        try sshz.requestWrite(
            try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr),
            .WriteCompletePreserveState,
        );
        chan.applyWindowAdjust(adjust);
        self.channel_window_adjust_in_flight = true;
        return true;
    }

    pub fn flushPendingChannelWindowAdjust(self: *Self, sshz: *SshzClient) SshzError!bool {
        if (self.pending_channel_replies_len != 0 or
            self.sessionState != .ChannelActive or self.is_rekeying or
            sshz.local_rekey_pending or sshz.iostate_rd == .Idle or
            sshz.iostate_wr != .Idle)
        {
            return false;
        }
        const chan = self.channel_table.findNextWindowAdjust() orelse return false;
        return try self.startChannelWindowAdjust(chan, sshz, &self.keydata.c2s);
    }

    fn finishChannelClose(self: *Self, chan: *Channel, sshz: *SshzClient) void {
        const local_id = chan.local_id;
        const kind = chan.kind;
        chan.state = .Closed;
        if (kind == .Session and chan.channel_type == .Session) {
            self.completeExitResult(local_id);
        }
        self.active_channel_id = null;
        if (kind == .AgentForward) {
            self.channel_table.freeChannel(local_id);
            sshz.requestEvent(.{ .AgentChannelClosed = local_id }, .Idle);
        } else {
            sshz.requestEvent(.{ .ChannelClosed = local_id }, .Idle);
        }
    }

    pub fn dispatchDeferredChannelWrite(self: *Self, sshz: *SshzClient) SshzError!bool {
        if (self.sessionState != .ChannelActive or self.is_rekeying or sshz.local_rekey_pending or
            sshz.iostate_wr != .Idle) return false;
        if (try self.flushPendingChannelReply(sshz)) return true;
        if (try self.flushPendingKeepalive(sshz)) return true;
        for (0..MaxChannels) |_| {
            const chan = self.channel_table.findNextDeferredWrite() orelse return false;
            if ((chan.close_received or chan.close_pending) and chan.tx_in_flight_len == 0) {
                chan.discardWriteBuffer();
                chan.eof_pending = false;
            }
            if (try self.startChannelWindowAdjust(chan, sshz, &self.keydata.c2s)) return true;
            if (!chan.eof_sent and !chan.close_sent and !chan.close_pending and !chan.close_received and
                chan.write_buf_nbytes > 0 and chan.tx_in_flight_len == 0 and chan.peer_window > 0)
            {
                return try self.startChannelWrite(chan, sshz, &self.keydata.c2s);
            }
            if (chan.write_buf_nbytes == 0 and chan.tx_in_flight_len == 0) {
                if (try self.startPendingChannelControl(chan, sshz, &self.keydata.c2s)) return true;
            }
        }
        return false;
    }

    pub fn completeChannelWindowAdjust(self: *Self, sshz: *SshzClient) SshzError!void {
        if (!self.channel_window_adjust_in_flight) return;
        self.channel_window_adjust_in_flight = false;
        _ = try self.dispatchDeferredChannelWrite(sshz);
    }

    pub fn channelReadConsumed(
        self: *Self,
        channel_id: u32,
        count: usize,
        sshz: *SshzClient,
    ) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse
            return IoError.UnexpectedResponse;
        if (chan.kind != .Session or chan.automatic_read_credit or
            chan.state == .Closed or chan.close_pending or chan.close_sent or chan.close_received)
        {
            return IoError.UnexpectedResponse;
        }
        try chan.queueReadCredit(count);
        _ = try self.dispatchDeferredChannelWrite(sshz);
    }

    pub fn releaseClosedChannel(self: *Self, channel_id: u32) SshzError!bool {
        const chan = self.channel_table.findByLocalId(channel_id) orelse
            return IoError.badClearEvent;
        if (chan.kind != .Session or chan.state != .Closed) {
            return IoError.badClearEvent;
        }
        self.channel_table.freeChannel(channel_id);
        self.active_channel_id = null;
        return self.shouldEndAfterChannelRelease();
    }

    pub fn shouldEndAfterChannelRelease(self: *const Self) bool {
        return self.auto_session_enabled and self.channel_table.activeCount() == 0;
    }

    pub fn completeChannelControl(self: *Self, channel_id: u32, sshz: *SshzClient) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        const control = chan.control_in_flight orelse return IoError.UnexpectedResponse;
        chan.control_in_flight = null;
        if (control == .Close) {
            if (chan.close_received) {
                self.finishChannelClose(chan, sshz);
                return;
            }
            const received_packet_pending = switch (self.ioSessionState) {
                .ReadPktCompletion => true,
                else => false,
            };
            if (!received_packet_pending) _ = try self.dispatchDeferredChannelWrite(sshz);
            return;
        }
        const received_packet_pending = switch (self.ioSessionState) {
            .ReadPktCompletion => true,
            else => false,
        };
        if (!received_packet_pending) {
            const queued = try self.startPendingChannelControl(chan, sshz, &self.keydata.c2s);
            if (!queued) _ = try self.dispatchDeferredChannelWrite(sshz);
        }
    }

    pub fn sendChannelEof(self: *Self, channel_id: u32, sshz: *SshzClient) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent or chan.eof_pending) return;
        if (chan.close_sent or chan.close_pending or chan.close_received) return IoError.UnexpectedResponse;
        chan.eof_pending = true;
        _ = try self.startPendingChannelControl(chan, sshz, &self.keydata.c2s);
    }

    pub fn channelEofFlushed(self: *Self, channel_id: u32) SshzError!bool {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.kind != .Session or chan.state == .Closed or
            chan.close_pending or chan.close_sent or chan.close_received)
        {
            return IoError.UnexpectedResponse;
        }
        if (!chan.remote_id_known) return false;
        return chan.eofFlushed();
    }

    pub fn sendChannelClose(self: *Self, channel_id: u32, sshz: *SshzClient) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.close_sent or chan.close_pending) return;
        chan.close_pending = true;
        chan.eof_pending = false;
        if (chan.tx_in_flight_len == 0) chan.discardWriteBuffer();
        _ = try self.startPendingChannelControl(chan, sshz, &self.keydata.c2s);
    }

    /// Queues a `window-change` request for the session channel.
    ///
    /// Only queues: the request goes out from `dispatchDeferredChannelWrite`,
    /// which is the point in `advance` where interjecting a packet is safe. A
    /// terminal is normally resized while nothing is being transmitted, so the
    /// caller is almost always arriving mid-read, and stealing the state
    /// machine then would abandon a read the transport is still expecting.
    pub fn sendWindowChange(self: *Self, cols: u32, rows: u32, width_px: u32, height_px: u32) void {
        self.pending_window_change = .{ cols, rows, width_px, height_px };
    }

    pub fn enableAgentForwarding(self: *Self) SshzError!void {
        if (!self.auto_session_enabled) return IoError.UnexpectedResponse;
        switch (self.sessionState) {
            .ChannelActive => return IoError.UnexpectedResponse,
            else => {
                self.agent_forwarding_enabled = true;
            },
        }
    }

    pub fn setAutoSessionEnabled(self: *Self, enabled: bool) SshzError!void {
        if (self.channel_table.activeCount() != 0 or self.user_authenticated) {
            return IoError.UnexpectedResponse;
        }
        if (!enabled and
            (self.agent_forwarding_enabled or self.auto_exec_command != null or self.auto_pty_requested))
        {
            return IoError.UnexpectedResponse;
        }
        self.auto_session_enabled = enabled;
    }

    pub fn setAutoChannelReadCreditEnabled(self: *Self, enabled: bool) SshzError!void {
        if (self.channel_table.activeCount() != 0) return IoError.UnexpectedResponse;
        self.auto_channel_read_credit_enabled = enabled;
    }

    pub fn setAutoExecCommand(self: *Self, command: []const u8) SshzError!void {
        if (!self.auto_session_enabled or self.channel_table.activeCount() != 0) {
            return IoError.UnexpectedResponse;
        }
        const replacement = try self.allocator.dupe(u8, command);
        self.clearAndFreeOptional(&self.auto_exec_command);
        self.auto_exec_command = replacement;
    }

    pub fn setAutoPty(self: *Self, term: []const u8, cols: u32, rows: u32, width_px: u32, height_px: u32) SshzError!void {
        if (!self.auto_session_enabled or self.channel_table.activeCount() != 0) {
            return IoError.UnexpectedResponse;
        }
        const replacement = try self.allocator.dupe(u8, term);
        self.clearAndFreeOptional(&self.auto_pty_term);
        self.auto_pty_term = replacement;
        self.auto_pty_cols = cols;
        self.auto_pty_rows = rows;
        self.auto_pty_width_px = width_px;
        self.auto_pty_height_px = height_px;
        self.auto_pty_requested = true;
    }

    pub fn setKeyboardInteractiveResponse(self: *Self, response: []const u8) SshzError!void {
        self.clearAndFreeOptional(&self.kbd_interactive_response);
        self.kbd_interactive_response = try self.allocator.dupe(u8, response);
    }

    pub fn setPrivateKey(self: *Self, keydata_ascii: []const u8) SshzError!void {
        if (self.privkey_ascii) |old| {
            std.crypto.secureZero(u8, old);
            self.allocator.free(old);
            self.privkey_ascii = null;
        }
        std.debug.assert(self.privkey_ascii == null);
        self.privkey_ascii = try self.allocator.dupe(u8, keydata_ascii);
    }

    pub fn setPrivateKeyPassphrase(self: *Self, data: []const u8) SshzError!void {
        if (self.privkey_passphrase) |old| {
            std.crypto.secureZero(u8, old);
            self.allocator.free(old);
            self.privkey_passphrase = null;
        }
        std.debug.assert(self.privkey_passphrase == null);
        self.privkey_passphrase = try self.allocator.dupe(u8, data);
    }

    pub fn setAuthPassphrase(self: *Self, data: []const u8) SshzError!void {
        if (self.auth_passphrase) |old| {
            std.crypto.secureZero(u8, old);
            self.allocator.free(old);
            self.auth_passphrase = null;
        }
        std.debug.assert(self.auth_passphrase == null);
        self.auth_passphrase = try self.allocator.dupe(u8, data);
    }

    // special case as we write direct to stream before entering binary pkt mode
    pub fn writeProtocolVersion(self: *Self, buf: []u8) []const u8 {
        const client_version = self.client_version.?;
        const vers = std.fmt.bufPrint(buf, "{s}\r\n", .{client_version}) catch unreachable;
        TRACE(.Debug, "TX: version '{s}'", .{client_version});
        self.kex_hash_order = self.kex_hash_order.check(.V_C);
        self.kex_hasher.writeU32LenString(client_version);
        return vers;
    }

    fn sendChannelOpenFailure(
        self: *Self,
        sshz: *SshzClient,
        recipient: u32,
        reason_code: u32,
        description: []const u8,
    ) SshzError!void {
        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
        try pkt.writeU32(recipient);
        try pkt.writeU32(reason_code);
        try pkt.writeU32LenString(description);
        try pkt.writeU32LenString("");
        try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.c2s, &pkt, &sshz.iobuf_wr), .Idle);
    }

    fn queueChannelReply(self: *Self, remote_id: u32, success: bool) SshzError!void {
        if (self.pending_channel_replies_len >= self.limits.max_channels)
            return IoError.ResourceLimitExceeded;
        const index = (self.pending_channel_replies_head + self.pending_channel_replies_len) % MaxChannels;
        self.pending_channel_replies[index] = .{ .remote_id = remote_id, .success = success };
        self.pending_channel_replies_len += 1;
    }

    fn flushPendingChannelReply(self: *Self, sshz: *SshzClient) SshzError!bool {
        if (self.pending_channel_replies_len == 0 or self.is_rekeying or
            sshz.local_rekey_pending or sshz.iostate_wr != .Idle)
        {
            return false;
        }

        const reply = self.pending_channel_replies[self.pending_channel_replies_head];
        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(if (reply.success)
            Protocol.MsgId.SSH_MSG_CHANNEL_SUCCESS
        else
            Protocol.MsgId.SSH_MSG_CHANNEL_FAILURE));
        try pkt.writeU32(reply.remote_id);
        try sshz.requestWrite(
            try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.c2s, &pkt, &sshz.iobuf_wr),
            .WriteCompletePreserveState,
        );
        self.pending_channel_replies_head = (self.pending_channel_replies_head + 1) % MaxChannels;
        self.pending_channel_replies_len -= 1;
        return true;
    }

    fn recordExitStatus(self: *Self, channel_id: u32, status: u32) void {
        const slot = self.findExitResultSlot(channel_id) orelse return;
        if (slot.result == null) slot.result = .{ .Status = status };
    }

    fn recordExitSignal(
        self: *Self,
        channel_id: u32,
        signal_name: []const u8,
        core_dumped: bool,
        error_message: []const u8,
        language_tag: []const u8,
    ) SshzError!void {
        const slot = self.findExitResultSlot(channel_id) orelse return;
        if (slot.result != null) return;

        const owned_signal_name = try self.allocator.dupe(u8, signal_name);
        errdefer self.allocator.free(owned_signal_name);
        const owned_error_message = try self.allocator.dupe(u8, error_message);
        errdefer self.allocator.free(owned_error_message);
        const owned_language_tag = try self.allocator.dupe(u8, language_tag);
        errdefer self.allocator.free(owned_language_tag);
        slot.result = .{ .Signal = .{
            .signal_name = owned_signal_name,
            .core_dumped = core_dumped,
            .error_message = owned_error_message,
            .language_tag = owned_language_tag,
        } };
    }

    fn handleChannelRequestPacket(
        self: *Self,
        rdr: *BufferReader,
        sshz: *SshzClient,
    ) SshzError!void {
        const channel_id = try rdr.readU32();
        const request_name = try rdr.readU32LenString();
        const want_reply = try rdr.readBoolean();
        const recognized_status = std.mem.eql(u8, request_name, Protocol.channel_request_exit_status);
        const recognized_signal = std.mem.eql(u8, request_name, Protocol.channel_request_exit_signal);

        var status: u32 = 0;
        var signal_name: []const u8 = "";
        var core_dumped = false;
        var error_message: []const u8 = "";
        var language_tag: []const u8 = "";
        if (recognized_status) {
            status = try rdr.readU32();
            if (rdr.off != rdr.payload.len) return IoError.UnexpectedResponse;
        } else if (recognized_signal) {
            signal_name = try rdr.readU32LenString();
            core_dumped = try rdr.readBoolean();
            error_message = try rdr.readU32LenString();
            language_tag = try rdr.readU32LenString();
            if (rdr.off != rdr.payload.len) return IoError.UnexpectedResponse;
        }

        const chan = self.channel_table.findByLocalId(channel_id);
        const valid_session = if (chan) |channel|
            channel.kind == .Session and channel.channel_type == .Session and channel.remote_id_known and
                !channel.close_pending and !channel.close_sent and !channel.close_received
        else
            false;

        if (valid_session and recognized_status) {
            self.recordExitStatus(channel_id, status);
        } else if (valid_session and recognized_signal) {
            try self.recordExitSignal(
                channel_id,
                signal_name,
                core_dumped,
                error_message,
                language_tag,
            );
        }

        if (want_reply) {
            if (chan) |channel| {
                if (channel.remote_id_known and !channel.close_sent and !channel.close_received) {
                    try self.queueChannelReply(
                        channel.remote_id,
                        valid_session and (recognized_status or recognized_signal),
                    );
                    _ = try self.flushPendingChannelReply(sshz);
                }
            }
        }
        self.setIoSessionState(.ReadPktHdr);
    }

    fn readTcpipOpen(rdr: *BufferReader) SshzError!TcpipOpen {
        return .{
            .host = try rdr.readU32LenString(),
            .port = try rdr.readU32(),
            .originator_host = try rdr.readU32LenString(),
            .originator_port = try rdr.readU32(),
        };
    }

    fn requestChannelOpenEvent(self: *Self, sshz: *SshzClient, chan: *Channel) void {
        _ = self;
        const request: Sshz.ChannelOpenRequestType = switch (chan.channel_type) {
            .Session => .Session,
            .DirectTcpip => .{ .DirectTcpip = .{
                .host = chan.tcpip_open.host,
                .port = chan.tcpip_open.port,
                .originator_host = chan.tcpip_open.originator_host,
                .originator_port = chan.tcpip_open.originator_port,
            } },
            .ForwardedTcpip => .{ .ForwardedTcpip = .{
                .connected_host = chan.tcpip_open.host,
                .connected_port = chan.tcpip_open.port,
                .originator_host = chan.tcpip_open.originator_host,
                .originator_port = chan.tcpip_open.originator_port,
            } },
        };
        sshz.requestEvent(.{ .ChannelOpenRequest = .{ .channel = chan.local_id, .request = request } }, .Idle);
    }

    fn handleChannelOpenPacket(self: *Self, rdr: *BufferReader, sshz: *SshzClient) SshzError!void {
        // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
        const chantype = try rdr.readU32LenString();
        const remote_id = try rdr.readU32();
        const peer_window = try rdr.readU32();
        const max_packet_size = try rdr.readU32();
        try self.validatePeerChannel(peer_window, max_packet_size);

        if (Protocol.isAgentChannelType(chantype)) {
            if (!self.agent_forwarding_enabled) {
                try self.sendChannelOpenFailure(
                    sshz,
                    remote_id,
                    SshOpenFailureReason.AdministrativelyProhibited,
                    "agent forwarding not enabled",
                );
                return;
            }

            const chan = self.channel_table.allocChannelKind(.AgentForward, remote_id, peer_window, max_packet_size) orelse {
                try self.sendChannelOpenFailure(
                    sshz,
                    remote_id,
                    SshOpenFailureReason.ResourceShortage,
                    "too many channels",
                );
                return;
            };
            chan.state = .ConfirmWrite;
            self.active_channel_id = chan.local_id;
            self.resumeChannelActive();
            self.setIoSessionState(.Idle);
            return;
        }

        const channel_type = ChannelType.fromName(chantype) orelse {
            try self.sendChannelOpenFailure(
                sshz,
                remote_id,
                SshOpenFailureReason.UnknownChannelType,
                "unknown channel type",
            );
            return;
        };

        if (channel_type == .Session) {
            try self.sendChannelOpenFailure(
                sshz,
                remote_id,
                SshOpenFailureReason.AdministrativelyProhibited,
                "client does not accept session channel opens",
            );
            return;
        }

        const tcpip_open = if (channel_type.hasTcpipOpenPayload()) try readTcpipOpen(rdr) else TcpipOpen{};
        const chan = self.channel_table.allocChannel(remote_id, peer_window, max_packet_size) orelse {
            try self.sendChannelOpenFailure(
                sshz,
                remote_id,
                SshOpenFailureReason.ResourceShortage,
                "too many channels",
            );
            return;
        };
        chan.channel_type = channel_type;
        chan.tcpip_open = tcpip_open;
        chan.automatic_read_credit = self.auto_channel_read_credit_enabled;
        chan.state = .Open;
        self.active_channel_id = null;
        self.resumeChannelActive();
        self.requestChannelOpenEvent(sshz, chan);
    }

    fn handleGlobalRequestSuccess(self: *Self, rdr: *BufferReader, sshz: *SshzClient) SshzError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        if (pending.transmission != .HandedToTransport) return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        switch (pending.kind) {
            .Keepalive => self.acknowledgeKeepalive(.Success),
            .TcpipForward => {
                const bound_port = if (pending.bind_port == 0) try rdr.readU32() else pending.bind_port;
                sshz.requestEvent(.{ .TcpipForwardSuccess = .{
                    .bind_address = pending.bind_address,
                    .requested_port = pending.bind_port,
                    .bound_port = bound_port,
                } }, .Idle);
            },
            .CancelTcpipForward => {
                sshz.requestEvent(.{ .CancelTcpipForwardSuccess = .{
                    .bind_address = pending.bind_address,
                    .bind_port = pending.bind_port,
                } }, .Idle);
            },
        }
    }

    fn handleGlobalRequestFailure(self: *Self, sshz: *SshzClient) SshzError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        if (pending.transmission != .HandedToTransport) return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        switch (pending.kind) {
            .Keepalive => self.acknowledgeKeepalive(.Failure),
            .TcpipForward => {
                sshz.requestEvent(.{ .TcpipForwardFailure = .{
                    .bind_address = pending.bind_address,
                    .bind_port = pending.bind_port,
                } }, .Idle);
            },
            .CancelTcpipForward => {
                sshz.requestEvent(.{ .CancelTcpipForwardFailure = .{
                    .bind_address = pending.bind_address,
                    .bind_port = pending.bind_port,
                } }, .Idle);
            },
        }
    }

    fn acknowledgeKeepalive(self: *Self, reply: Sshz.KeepaliveReply) void {
        if (self.keepalive) |*status| {
            if (status.outcome == .Pending) status.outcome = .{ .Acknowledged = reply };
        }
        self.setIoSessionState(.ReadPktHdr);
    }

    /// RFC 4252 userauth replies drive `sessionState` directly, so one accepted
    /// outside the authentication phase would overwrite whatever state the
    /// session is parked in. A malicious server could otherwise send KEXINIT
    /// mid-userauth and then USERAUTH_SUCCESS, stranding the re-key: KEX_ECDH_INIT
    /// would never be sent and `is_rekeying` would stay latched forever. The
    /// server side already fails closed on out-of-phase auth messages.
    fn isAwaitingUserauthReply(self: *const Self) bool {
        return switch (self.sessionState) {
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
            => true,
            else => false,
        };
    }

    /// RFC 4250 §4.1.2 reserves message numbers 80-127 for the connection
    /// protocol, which is only reachable after `ssh-userauth` succeeds. This is
    /// a latch rather than a `sessionState` test because RFC 4253 §9 allows
    /// connection-protocol packets sent before a re-key to still arrive while
    /// `sessionState` is temporarily back in the key-exchange states.
    fn isAuthenticatedForConnectionProtocol(self: *const Self) bool {
        return self.user_authenticated;
    }

    pub fn handlePacket(self: *Self, buf: []const u8, sshz: *SshzClient) SshzError!void {
        var rdr = try sshz.getRecvBuffer(sshz.iobuf_rd[0..buf.len], &self.keydata.s2c);

        const msgid = try rdr.readU8();
        try sshz.accountInboundMessage(msgid);

        TRACE(.Debug, "handlePacket msgId={d}", .{msgid});
        UNSAFE_TRACEDUMP(.Debug, "handlePacket", .{}, buf);

        if (self.ignore_next_kex_packet) {
            self.ignore_next_kex_packet = false;
            self.setIoSessionState(.ReadPktHdr);
            return;
        }

        if (msgid >= Protocol.connection_protocol_msgid_min and
            msgid <= Protocol.connection_protocol_msgid_max and
            !self.isAuthenticatedForConnectionProtocol())
        {
            return IoError.UnexpectedResponse;
        }

        switch (msgid) {
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS),
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE),
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK),
            => if (!self.isAwaitingUserauthReply()) return IoError.UnexpectedResponse,
            else => {},
        }

        switch (msgid) {
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT) => {
                errdefer self.clearKexState();
                TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                const initial_kex = self.sessionState == .KexInitRead and !self.is_rekeying and
                    !self.encrypted and !self.inbound_encrypted;
                const local_or_simultaneous_rekey = self.sessionState == .KexInitRead and self.is_rekeying;
                const peer_initiated_rekey = !initial_kex and !local_or_simultaneous_rekey;
                if (peer_initiated_rekey) {
                    // RFC 4253 §9 - peer-initiated re-keying is only valid once the
                    // initial key exchange has completed (i.e. session_id exists).
                    if (!self.session_id_established) return IoError.UnexpectedResponse;
                    TRACE(.Info, "Re-keying initiated by peer", .{});
                    try self.startPeerRekey(rdr.payload[(rdr.off - 1)..]);
                } else {
                    self.kex_hash_order = self.kex_hash_order.check(.I_S);
                    self.kex_hasher.writeU32LenString(rdr.payload[(rdr.off - 1)..]); // from before the msgid
                }

                // RFC 4253 §7.1: every selection follows the client's order.
                const peer_kexinit = try Protocol.readKexInit(&rdr);
                const negotiated = try Protocol.negotiateAlgorithms(
                    peer_kexinit,
                    .Client,
                    Key.client_hostkey_algorithms,
                );
                self.selected_hostkey_algorithm = Key.SignatureAlgorithm.fromName(negotiated.host_key) orelse
                    return IoError.AlgorithmNegotiationFailed;
                self.negotiated_compression_c2s = negotiated.compression_c2s;
                self.negotiated_compression_s2c = negotiated.compression_s2c;
                self.ignore_next_kex_packet = negotiated.ignore_next_peer_packet;

                if (peer_initiated_rekey) {
                    self.setSessionState(.KexInitWrite);
                    self.setIoSessionState(.Idle);
                } else if (initial_kex or local_or_simultaneous_rekey) {
                    self.setSessionState(.EcdhInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY) => {
                if (self.sessionState == .EcdhReply) {
                    errdefer self.clearKexState();
                    TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                    const server_hostkey = try rdr.readU32LenString();
                    UNSAFE_TRACEDUMP(.Debug, "server_hostkey", .{}, server_hostkey);

                    const srv_pub_ephem = try rdr.readU32LenString();
                    UNSAFE_TRACEDUMP(.Debug, "srv_pub_ephem: (len={d})", .{srv_pub_ephem.len}, srv_pub_ephem);
                    if (srv_pub_ephem.len != Protocol.kex_algo.public_length) {
                        return IoError.UnexpectedResponse;
                    }

                    // In form U32LenString("ssh-ed25519"), U32LenString(hash)
                    const sig_exch_hash = try rdr.readU32LenString();
                    defer std.crypto.secureZero(u8, @constCast(sig_exch_hash));
                    UNSAFE_TRACEDUMP(.Debug, "sig_exch_hash: (len={d})", .{sig_exch_hash.len}, sig_exch_hash);
                    if (rdr.off != rdr.payload.len) return IoError.UnexpectedResponse;

                    self.kex_hash_order = self.kex_hash_order.check(.K_S);
                    self.kex_hasher.writeU32LenString(server_hostkey);

                    self.kex_hash_order = self.kex_hash_order.check(.Q_C);
                    self.kex_hasher.writeU32LenString(&self.ecdh_ephem_keypair.public_key);

                    self.kex_hash_order = self.kex_hash_order.check(.Q_S);
                    self.kex_hasher.writeU32LenString(srv_pub_ephem);

                    // generate shared secret
                    var shared_secret = try Protocol.kex_algo.scalarmult(
                        self.ecdh_ephem_keypair.secret_key,
                        srv_pub_ephem[0..Protocol.kex_algo.public_length].*,
                    );
                    defer std.crypto.secureZero(u8, &shared_secret);
                    @memcpy(&self.shared_secret_k, &shared_secret);
                    self.clearEphemeralKeyPair();

                    UNSAFE_TRACEDUMP(.Debug, "shared secret len={d}", .{self.shared_secret_k.len}, &self.shared_secret_k);

                    self.kex_hash_order = self.kex_hash_order.check(.K);
                    self.kex_hasher.writeMpint(&self.shared_secret_k);

                    // Produce H/session_id/key exchange hash
                    // Both sides now have this
                    var kexhash: [Protocol.hash_algo.digest_length]u8 = undefined; // session_id, H
                    defer std.crypto.secureZero(u8, &kexhash);
                    self.kex_hasher.final(&kexhash, null);
                    UNSAFE_TRACEDUMP(.Debug, "kexhash: (len={d})", .{kexhash.len}, &kexhash);

                    const selected_sig_alg = self.selected_hostkey_algorithm orelse return IoError.UnexpectedResponse;
                    const sig_alg = try Key.signatureAlgorithm(sig_exch_hash);
                    if (sig_alg != selected_sig_alg) return IoError.AlgorithmNegotiationFailed;
                    const pubkey = try Key.parsePublicKeyBlob(server_hostkey);
                    if (pubkey.algorithm() != selected_sig_alg.keyAlgorithm()) return IoError.AlgorithmNegotiationFailed;
                    try Key.verifySignature(pubkey, sig_exch_hash, &kexhash);

                    // Only a signature-verified key reaches initial trust policy or rekey binding.
                    try self.bindVerifiedHostKey(server_hostkey);
                    try self.installExchangeKeys(kexhash);
                    self.clearKexState();
                    std.crypto.secureZero(u8, &sshz.iobuf_rd);
                    std.crypto.secureZero(u8, &sshz.iobuf_decompressed);
                    sshz.rd_nbytes = 0;
                    sshz.rd_off = 0;

                    self.setSessionState(.CheckHostKey);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS) => {
                if (self.sessionState == .NewKeysRead) {
                    try self.activatePendingS2cKeys(sshz);
                    self.setSessionState(.NewKeysWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_ACCEPT) => {
                if (self.sessionState == .AuthServRsp) {
                    self.setSessionState(.AuthStart);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_BANNER) => {
                // RFC 4252 §5.4 - banner message before auth completes
                const banner = try rdr.readU32LenString();
                TRACE(.Debug, "Server banner len={d}", .{util.chomp(banner).len});
                _ = try rdr.readU32LenString(); // language tag
                sshz.requestEvent(.{ .Banner = banner }, .ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS) => {
                if (self.current_auth_method == null) return IoError.UnexpectedResponse;
                self.clearPrivateKeyMaterial();
                self.clearAndFreeOptional(&self.auth_passphrase);
                self.clearAndFreeOptional(&self.kbd_interactive_response);
                try self.activateDelayedCompression();
                self.user_authenticated = true;
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelOpenReq);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE) => {
                const methods = try rdr.readU32LenString();
                const partial_success = try rdr.readBoolean();
                const attempted_method = self.current_auth_method orelse return IoError.UnexpectedResponse;
                const failure = self.rememberAuthFailure(attempted_method, methods, partial_success);
                if (partial_success) self.beginNextAuthStage();
                self.setIoSessionState(.Idle);
                try self.continueAuthentication(sshz, failure);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK) => {
                // RFC 4256 §3.3 - SSH_MSG_USERAUTH_INFO_REQUEST (same msg id as PK_OK)
                const name = try rdr.readU32LenString();
                const instruction = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag
                const num_prompts = try rdr.readU32();
                if (num_prompts > 0) {
                    const prompt = try rdr.readU32LenString();
                    const echo = try rdr.readBoolean();
                    sshz.requestEvent(.{ .KeyboardInteractive = .{
                        .name = name,
                        .instruction = instruction,
                        .prompt = prompt,
                        .echo = echo,
                    } }, .Idle);
                    self.setSessionState(.KeyboardInteractiveInfoRsp);
                } else {
                    // Zero prompts — send empty response
                    self.setSessionState(.KeyboardInteractiveInfoRsp);
                    self.setIoSessionState(.Idle);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS) => {
                try self.handleGlobalRequestSuccess(&rdr, sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE) => {
                try self.handleGlobalRequestFailure(sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN) => {
                try self.handleChannelOpenPacket(&rdr, sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                const recipient = try rdr.readU32(); // recipient channel
                const sender = try rdr.readU32(); // sender channel
                const peer_window = try rdr.readU32(); // initial window size
                const max_packet_size = try rdr.readU32(); // maximum packet size
                try self.validatePeerChannel(peer_window, max_packet_size);
                if (self.channel_table.findByLocalId(recipient)) |chan| {
                    chan.remote_id = sender;
                    chan.remote_id_known = true;
                    chan.peer_window = peer_window;
                    chan.remote_max_packet_size = max_packet_size;
                    switch (chan.client_open_mode) {
                        .AutoShell, .AutoExec => if (chan.channel_type == .Session) {
                            chan.state = .Open;
                            self.active_channel_id = chan.local_id;
                            self.resumeChannelActive();
                            self.setIoSessionState(.Idle);
                        } else return IoError.UnexpectedResponse,
                        .RawSession => {
                            chan.state = .Data;
                            self.active_channel_id = chan.local_id;
                            self.resumeChannelActive();
                            sshz.requestEvent(.{ .ChannelOpened = chan.local_id }, .Idle);
                        },
                    }
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                const recipient = try rdr.readU32(); // recipient channel
                const reason_code = try rdr.readU32();
                const description = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag

                if (self.channel_table.findByLocalId(recipient)) |chan| {
                    const local_id = chan.local_id;
                    if (chan.kind == .Session and chan.channel_type == .Session) {
                        self.releaseExitResultReservation(local_id);
                    }
                    self.channel_table.freeChannel(local_id);
                    self.active_channel_id = null;
                    self.resumeChannelActive();
                    sshz.requestEvent(.{ .ChannelOpenFailure = .{
                        .channel = local_id,
                        .reason_code = reason_code,
                        .description = description,
                    } }, .Idle);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                if (chan.eof_received) {
                    TRACE(.Debug, "discarding data after EOF on channel {d}", .{channelnum});
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                }
                if (chan.state != .DataRx) {
                    return IoError.UnexpectedResponse;
                }
                const s = try rdr.readU32LenString();
                try chan.consumeReceivedData(s.len);
                switch (chan.kind) {
                    .Session => sshz.requestEvent(.{ .RxData = .{ .channel = chan.local_id, .data = s } }, .Idle),
                    .AgentForward => sshz.requestEvent(.{ .AgentData = .{ .channel = chan.local_id, .data = s } }, .Idle),
                }
                chan.state = .Data;
                self.active_channel_id = chan.local_id;
                self.resumeChannelActive();
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                if (chan.eof_received) {
                    TRACE(.Debug, "discarding extended data after EOF on channel {d}", .{channelnum});
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                }
                if (chan.state != .DataRx) {
                    return IoError.UnexpectedResponse;
                }
                const data_type = try rdr.readU32();
                const s = try rdr.readU32LenString();
                try chan.consumeReceivedData(s.len);
                sshz.requestEvent(.{ .RxExtendedData = .{
                    .channel = chan.local_id,
                    .data_type = data_type,
                    .data = s,
                } }, .Idle);
                chan.state = .Data;
                self.active_channel_id = chan.local_id;
                self.resumeChannelActive();
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST) => {
                try self.handleChannelRequestPacket(&rdr, sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT) => {
                // RFC 4253 §11.1
                const reason_code = try rdr.readU32();
                const description = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag
                TRACE(.Info, "SSH_MSG_DISCONNECT reason={d} description_len={d}", .{ reason_code, description.len });
                sshz.requestEvent(.{ .EndSession = .{ .ServerDisconnect = .{
                    .code = reason_code,
                    .description = description,
                } } }, .Idle);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF) => {
                const channelnum = try rdr.readU32();
                if (self.channel_table.findByLocalId(channelnum)) |chan| {
                    if (chan.eof_received) {
                        self.setIoSessionState(.ReadPktHdr);
                        return;
                    }
                    chan.eof_received = true;
                    if (chan.kind == .Session) {
                        self.active_channel_id = chan.local_id;
                        self.resumeChannelActive();
                        sshz.requestEvent(.{ .ChannelEof = chan.local_id }, .Idle);
                        return;
                    }
                    if (chan.write_buf_nbytes > 0 or chan.eof_pending or chan.close_pending) {
                        self.active_channel_id = chan.local_id;
                        self.resumeChannelActive();
                        self.setIoSessionState(.Idle);
                        return;
                    }
                }
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                chan.close_received = true;
                chan.discardWriteBuffer();
                chan.eof_pending = false;
                if (chan.close_sent) {
                    self.finishChannelClose(chan, sshz);
                } else {
                    self.active_channel_id = chan.local_id;
                    chan.close_pending = true;
                    chan.state = .DataRx;
                    self.resumeChannelActive();
                    self.setIoSessionState(.Idle);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE) => {
                // RFC 4253 §11.2 - must be silently ignored
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_DEBUG) => {
                // RFC 4253 §11.3 - may be logged, must not cause protocol failure
                const always_display = try rdr.readBoolean();
                const message = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag
                if (always_display) {
                    TRACE(.Info, "SSH_MSG_DEBUG message_len={d}", .{message.len});
                } else {
                    TRACE(.Debug, "SSH_MSG_DEBUG message_len={d}", .{message.len});
                }
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST) => {
                // RFC 4254 §5.2 - peer is granting more window
                const channelnum = try rdr.readU32();
                if (self.channel_table.findByLocalId(channelnum)) |chan| {
                    const bytes_to_add = try rdr.readU32();
                    try chan.adjustPeerWindow(bytes_to_add, self.limits.max_channel_window);
                    if (chan.write_buf_nbytes > 0) {
                        self.active_channel_id = chan.local_id;
                        self.resumeChannelActive();
                        self.setIoSessionState(.Idle);
                        return;
                    }
                } else {
                    _ = try rdr.readU32();
                }
                self.setIoSessionState(.ReadPktHdr);
            },
            else => {
                // unhandled packet type
                TRACE(.Info, "Unhandled msg id={d}", .{msgid});
                self.setIoSessionState(.ReadPktHdr); // read again
            },
        }
    }
};

// Helper: build an unencrypted SSH packet in the provided buffer.
// Returns the total packet length (header + payload + padding).
fn buildUnencryptedPacket(buf: []u8, payload: []const u8) usize {
    const padding_length: u8 = 8;
    const packet_length: u32 = @intCast(payload.len + padding_length + 1);
    // Build PktHdr the same way wrapPkt does
    const hdr: Protocol.PktHdr = .{
        .packet_length = packet_length,
        .padding_length = padding_length,
    };
    std.mem.writeInt(u32, buf[0..4], hdr.packet_length, .big);
    buf[4] = hdr.padding_length;
    @memcpy(buf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload.len], payload);
    @memset(buf[Protocol.sizeof_PktHdr + payload.len .. Protocol.sizeof_PktHdr + payload.len + padding_length], 0);
    return Protocol.sizeof_PktHdr + payload.len + padding_length;
}

fn unencryptedPayload(packet: []const u8) []const u8 {
    const hdr = Protocol.readPktHdr(packet[0..Protocol.sizeof_PktHdr]);
    const payload_len = hdr.packet_length - hdr.padding_length - 1;
    return packet[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];
}

fn decryptFirstBlockForTest(packet: []u8, keys: *Protocol.KeyDataUni) !void {
    var encrypted_block: [Protocol.AesCtrT.block_size]u8 = undefined;
    @memcpy(&encrypted_block, packet[0..Protocol.AesCtrT.block_size]);
    try keys.aesctr.encrypt(&encrypted_block, packet[0..Protocol.AesCtrT.block_size]);
    keys.seq += 1;
}

fn consumeProducedChannelDataForTest(m: *SshzClient, destination: []u8, offset: usize) !usize {
    const packet = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA), try rdr.readU8());
    _ = try rdr.readU32();
    const data = try rdr.readU32LenString();
    @memcpy(destination[offset .. offset + data.len], data);
    try m.consumed(packet.len);
    return data.len;
}

fn buildAuthFailurePacket(m: *SshzClient, methods: []const u8, partial_success: bool) !usize {
    var payload_backing: [256]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE));
    try payload.writeU32LenString(methods);
    try payload.writeBoolean(partial_success);
    return buildUnencryptedPacket(&m.iobuf_rd, payload.active());
}

fn deliverChannelRequestForTest(
    m: *SshzClient,
    channel_id: u32,
    request_name: []const u8,
    want_reply: bool,
    request_payload: []const u8,
) !void {
    var payload_backing: [512]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
    try payload.writeU32(channel_id);
    try payload.writeU32LenString(request_name);
    try payload.writeBoolean(want_reply);
    try payload.writeBytes(request_payload);
    const packet_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
    m.session.user_authenticated = true;
    try m.session.handlePacket(m.iobuf_rd[0..packet_len], m);
}

fn expectChannelReplyForTest(m: *SshzClient, msgid: Protocol.MsgId, remote_id: u32) !void {
    const packet = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(packet));
    try std.testing.expectEqual(@intFromEnum(msgid), try rdr.readU8());
    try std.testing.expectEqual(remote_id, try rdr.readU32());
    try std.testing.expectEqual(rdr.payload.len, rdr.off);
    try m.consumed(packet.len);
}

fn writeKexInitPayload(writer: *BufferWriter) !void {
    try writeKexInitPayloadWithGuess(
        writer,
        Protocol.kex_algorithms,
        Protocol.srv_hostkey_algo_name,
        false,
    );
}

fn writeKexInitPayloadWithGuess(
    writer: *BufferWriter,
    kex_algorithms: []const u8,
    host_key_algorithms: []const u8,
    first_kex_packet_follows: bool,
) !void {
    try writer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
    const cookie: [16]u8 = .{0x5a} ** 16;
    try writer.writeBytes(&cookie);
    try writer.writeU32LenString(kex_algorithms);
    try writer.writeU32LenString(host_key_algorithms);
    try writer.writeU32LenString(Protocol.encryption_algorithms);
    try writer.writeU32LenString(Protocol.encryption_algorithms);
    try writer.writeU32LenString(Protocol.mac_algorithms);
    try writer.writeU32LenString(Protocol.mac_algorithms);
    try writer.writeU32LenString(Protocol.compression_algorithms);
    try writer.writeU32LenString(Protocol.compression_algorithms);
    try writer.writeU32LenString("");
    try writer.writeU32LenString("");
    try writer.writeBoolean(first_kex_packet_follows);
    try writer.writeU32(0);
}

test "client ignores exactly one packet after an incorrect KEX guess" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var kexinit_backing: [512]u8 = undefined;
    var kexinit = BufferWriter.init(&kexinit_backing, 0);
    try writeKexInitPayloadWithGuess(
        &kexinit,
        "unsupported-kex,curve25519-sha256",
        "rsa-sha2-256,ssh-ed25519",
        true,
    );
    const kexinit_packet_len = buildUnencryptedPacket(&m.iobuf_rd, kexinit.active());
    m.session.kex_hash_order = .I_C;
    m.session.setSessionState(.KexInitRead);
    try m.session.handlePacket(m.iobuf_rd[0..kexinit_packet_len], &m);
    try std.testing.expect(m.session.ignore_next_kex_packet);

    const guessed_packet_len = buildUnencryptedPacket(
        &m.iobuf_rd,
        &.{@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY)},
    );
    m.session.setSessionState(.EcdhReply);
    try m.session.handlePacket(m.iobuf_rd[0..guessed_packet_len], &m);
    try std.testing.expect(!m.session.ignore_next_kex_packet);
    try std.testing.expectEqual(SessionState.EcdhReply, m.session.sessionState);
    try std.testing.expectError(
        BufferError.ReaderOutOfDataErr,
        m.session.handlePacket(m.iobuf_rd[0..guessed_packet_len], &m),
    );
}

test "client rejects malformed ECDH reply public key lengths" {
    const public_length = Protocol.kex_algo.public_length;
    const malformed_lengths = [_]usize{ 0, public_length - 1, public_length + 1 };
    const public_key: [public_length + 1]u8 = .{0x42} ** (public_length + 1);

    for (malformed_lengths) |length| {
        var prng = std.Random.DefaultPrng.init(42);
        var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
        defer m.deinit();

        var payload_backing: [128]u8 = undefined;
        var payload = BufferWriter.init(&payload_backing, 0);
        try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY));
        try payload.writeU32LenString("");
        try payload.writeU32LenString(public_key[0..length]);
        try payload.writeU32LenString("");

        const packet_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
        m.session.setSessionState(.EcdhReply);
        try std.testing.expectError(
            IoError.UnexpectedResponse,
            m.session.handlePacket(m.iobuf_rd[0..packet_len], &m),
        );
        try std.testing.expect(!m.session.ecdh_ephem_keypair_active);
        try std.testing.expect(!m.session.kex_hasher.active);
        for (m.session.shared_secret_k) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "client rejects truncated ECDH reply public key data" {
    const public_length = Protocol.kex_algo.public_length;
    const truncated_public_key: [public_length - 1]u8 = .{0x42} ** (public_length - 1);

    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY));
    try payload.writeU32LenString("");
    try payload.writeU32(public_length);
    try payload.writeBytes(&truncated_public_key);

    const packet_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
    m.session.setSessionState(.EcdhReply);
    try std.testing.expectError(
        BufferError.ReaderOutOfDataErr,
        m.session.handlePacket(m.iobuf_rd[0..packet_len], &m),
    );
    try std.testing.expect(!m.session.ecdh_ephem_keypair_active);
    try std.testing.expect(!m.session.kex_hasher.active);
    for (m.session.shared_secret_k) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

fn expectQueuedAuthMethodStarted(m: *SshzClient, expected_method: AuthMethod) !void {
    var ready_opt: ?Sshz.SshzEvent(.Client) = null;
    for (0..4) |_| {
        ready_opt = m.getNextEvent() catch |err| switch (err) {
            error.NotReady => continue,
            else => return err,
        };
        break;
    }
    const ready = ready_opt orelse return error.TestUnexpectedResult;
    switch (ready) {
        .ReadyToProduce, .ReadyToConsumeAndProduce => {},
        else => return error.TestUnexpectedResult,
    }

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST), try rdr.readU8());
    try std.testing.expectEqualStrings("testuser", try rdr.readU32LenString());
    try std.testing.expectEqualStrings("ssh-connection", try rdr.readU32LenString());
    try std.testing.expectEqualStrings(expected_method.name(), try rdr.readU32LenString());
    try m.consumed(data.len);

    const started = try m.getNextEvent();
    switch (started) {
        .Event => |code| switch (code) {
            .AuthMethodStarted => |method| try std.testing.expectEqual(expected_method, method),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

fn expectProducedChannelRequest(m: *SshzClient, expected_type: []const u8) !void {
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST), try rdr.readU8());
    _ = try rdr.readU32(); // recipient channel
    try std.testing.expectEqualStrings(expected_type, try rdr.readU32LenString());
}

fn expectProducedPtyRequest(
    m: *SshzClient,
    expected_term: []const u8,
    expected_cols: u32,
    expected_rows: u32,
    expected_width_px: u32,
    expected_height_px: u32,
) !void {
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST), try rdr.readU8());
    _ = try rdr.readU32(); // recipient channel
    try std.testing.expectEqualStrings("pty-req", try rdr.readU32LenString());
    try std.testing.expect(!(try rdr.readBoolean()));
    try std.testing.expectEqualStrings(expected_term, try rdr.readU32LenString());
    try std.testing.expectEqual(expected_cols, try rdr.readU32());
    try std.testing.expectEqual(expected_rows, try rdr.readU32());
    try std.testing.expectEqual(expected_width_px, try rdr.readU32());
    try std.testing.expectEqual(expected_height_px, try rdr.readU32());
}

fn expectProducedExecRequest(m: *SshzClient, expected_command: []const u8) !void {
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST), try rdr.readU8());
    _ = try rdr.readU32(); // recipient channel
    try std.testing.expectEqualStrings("exec", try rdr.readU32LenString());
    try std.testing.expect(!(try rdr.readBoolean()));
    try std.testing.expectEqualStrings(expected_command, try rdr.readU32LenString());
}

fn confirmAutoSessionChannel(m: *SshzClient, mode: ClientChannelOpenMode) !*Channel {
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = mode;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id);
    try pw.writeU32(42);
    try pw.writeU32(32768);
    try pw.writeU32(4096);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelOpenRsp);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], m);
    try std.testing.expectEqual(ChannelState.Open, chan.state);
    return chan;
}

fn deliverChannelControlForTest(
    m: *SshzClient,
    message: Protocol.MsgId,
    channel_id: u32,
) !void {
    var payload: [5]u8 = undefined;
    payload[0] = @intFromEnum(message);
    std.mem.writeInt(u32, payload[1..5], channel_id, .big);
    const packet_len = buildUnencryptedPacket(&m.iobuf_rd, &payload);
    m.iostate_rd = .Idle;
    try m.session.handlePacket(m.iobuf_rd[0..packet_len], m);
}

fn expectChannelEofForTest(m: *SshzClient, channel_id: u32) !void {
    switch (try m.getNextEvent()) {
        .Event => |event| switch (event) {
            .ChannelEof => |received_id| try std.testing.expectEqual(channel_id, received_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

fn expectChannelClosedForTest(m: *SshzClient, channel_id: u32) !void {
    switch (try m.getNextEvent()) {
        .Event => |event| switch (event) {
            .ChannelClosed => |received_id| try std.testing.expectEqual(channel_id, received_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

fn expectAgentChannelClosedForTest(m: *SshzClient, channel_id: u32) !void {
    switch (try m.getNextEvent()) {
        .Event => |event| switch (event) {
            .AgentChannelClosed => |received_id| try std.testing.expectEqual(channel_id, received_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

fn expectDisconnectForTest(m: *SshzClient) !void {
    switch (try m.getNextEvent()) {
        .Event => |event| switch (event) {
            .EndSession => |reason| switch (reason) {
                .Disconnect => {},
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

fn openConfirmedDirectTcpipForTest(
    m: *SshzClient,
    remote_id: u32,
    originator_port: u32,
) !u32 {
    const channel_id = try m.openDirectTcpipChannel(
        "example.com",
        443,
        "127.0.0.1",
        originator_port,
    );
    const open_packet = try m.peek(Protocol.MaxSSHPacket);
    try m.consumed(open_packet.len);

    var confirmation_backing: [32]u8 = undefined;
    var confirmation = BufferWriter.init(&confirmation_backing, 0);
    try confirmation.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try confirmation.writeU32(channel_id);
    try confirmation.writeU32(remote_id);
    try confirmation.writeU32(32768);
    try confirmation.writeU32(4096);
    const confirmation_len = buildUnencryptedPacket(&m.iobuf_rd, confirmation.active());
    m.iostate_rd = .Idle;
    try m.session.handlePacket(m.iobuf_rd[0..confirmation_len], m);
    switch (try m.getNextEvent()) {
        .Event => |event| switch (event) {
            .ChannelOpened => |opened_id| try std.testing.expectEqual(channel_id, opened_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try m.clearEvent(.{ .ChannelOpened = channel_id });
    return channel_id;
}

fn expectWindowAdjustForTest(
    m: *SshzClient,
    remote_id: u32,
    amount: u32,
) !void {
    const packet = try m.peek(Protocol.MaxSSHPacket);
    var reader = BufferReader.init(unencryptedPayload(packet));
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST),
        try reader.readU8(),
    );
    try std.testing.expectEqual(remote_id, try reader.readU32());
    try std.testing.expectEqual(amount, try reader.readU32());
    try m.consumed(packet.len);
}

fn sendChannelDataForTest(
    m: *SshzClient,
    channel_id: u32,
    remote_id: u32,
    byte: u8,
) !void {
    const destination = try m.getChannelWriteBuffer(channel_id);
    destination[0] = byte;
    try m.channelWriteComplete(channel_id, 1);
    const packet = try m.peek(Protocol.MaxSSHPacket);
    var reader = BufferReader.init(unencryptedPayload(packet));
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA),
        try reader.readU8(),
    );
    try std.testing.expectEqual(remote_id, try reader.readU32());
    try std.testing.expectEqualSlices(u8, destination[0..1], try reader.readU32LenString());
    try m.consumed(packet.len);
}

test "none auth queues request before method-started event" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.setTryNoneAuth(true);
    m.session.encrypted = false;
    m.session.setSessionState(.AuthStart);
    m.session.setIoSessionState(.Idle);

    try expectQueuedAuthMethodStarted(&m, .None);
    try m.clearEvent(.{ .AuthMethodStarted = .None });
    const next = try m.getNextEvent();
    switch (next) {
        .ReadyToConsume => {},
        else => return error.TestUnexpectedResult,
    }
}

test "none auth success advances without requesting credentials" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.current_auth_method = .None;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = 1;
    m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.None)] = 1;
    m.session.setSessionState(.AuthRsp);
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    var payload = [_]u8{@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS)};
    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, &payload);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expectEqual(SessionState.ChannelOpenReq, m.session.sessionState);
    try std.testing.expect(m.session.privkey_ascii == null);
    try std.testing.expect(m.session.auth_passphrase == null);
}

test "disabled auto session emits Connected without consuming a channel slot" {
    var prng = std.Random.DefaultPrng.init(42);
    var limits: Sshz.ResourceLimits = .{};
    limits.max_channels = 1;
    var m = try SshzClient.initWithLimits(
        prng.random(),
        "testuser",
        std.testing.allocator,
        limits,
    );
    defer m.deinit();

    try m.setAutoSessionEnabled(false);
    m.session.encrypted = false;
    m.session.current_auth_method = .None;
    m.session.setSessionState(.AuthRsp);
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    var payload = [_]u8{@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS)};
    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, &payload);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try m.advance();

    try std.testing.expectEqual(SessionState.ChannelActive, m.session.sessionState);
    try std.testing.expectEqual(@as(u32, 0), m.session.channel_table.activeCount());
    const event = try m.getNextEvent();
    switch (event) {
        .Event => |code| switch (code) {
            .Connected => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try m.clearEvent(.Connected);
    const channel_id = try m.openDirectTcpipChannel("example.com", 443, "127.0.0.1", 55555);
    try std.testing.expectEqual(@as(u32, 0), channel_id);
    try std.testing.expectEqual(@as(u32, 1), m.session.channel_table.activeCount());
}

test "configured channel capacity supports concurrent tunnel channels" {
    const runtime_channel_limit: u8 = 8;
    if (MaxChannels < runtime_channel_limit) return error.SkipZigTest;

    var prng = std.Random.DefaultPrng.init(42);
    var limits: Sshz.ResourceLimits = .{};
    limits.max_channels = runtime_channel_limit;
    var m = try SshzClient.initWithLimits(
        prng.random(),
        "testuser",
        std.testing.allocator,
        limits,
    );
    defer m.deinit();

    try m.setAutoSessionEnabled(false);
    m.session.encrypted = false;
    m.session.current_auth_method = .None;
    m.session.setSessionState(.AuthRsp);
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    var auth_payload = [_]u8{@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS)};
    const auth_packet_len = buildUnencryptedPacket(&m.iobuf_rd, &auth_payload);
    try m.session.handlePacket(m.iobuf_rd[0..auth_packet_len], &m);
    try m.advance();
    try m.clearEvent(.Connected);

    var channel_ids: [runtime_channel_limit]u32 = undefined;
    for (&channel_ids, 0..) |*channel_id, index| {
        channel_id.* = try openConfirmedDirectTcpipForTest(
            &m,
            @intCast(100 + index),
            @intCast(50_000 + index),
        );
    }

    try std.testing.expectEqual(@as(u32, runtime_channel_limit), m.session.channel_table.activeCount());
    try std.testing.expectError(
        IoError.tooManyChannels,
        m.openDirectTcpipChannel("example.com", 443, "127.0.0.1", 60_000),
    );

    for (channel_ids, 0..) |channel_id, index| {
        var expected = [_]u8{@as(u8, @intCast(index + 1))};
        try expectChannelData(&m, channel_id, &expected);
    }

    for (channel_ids, 0..) |channel_id, index| {
        const destination = try m.getChannelWriteBuffer(channel_id);
        destination[0] = @intCast(index + 11);
        try m.channelWriteComplete(channel_id, 1);

        const data_packet = try m.peek(Protocol.MaxSSHPacket);
        var data_reader = BufferReader.init(unencryptedPayload(data_packet));
        try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA), try data_reader.readU8());
        try std.testing.expectEqual(@as(u32, @intCast(100 + index)), try data_reader.readU32());
        try std.testing.expectEqualSlices(u8, destination[0..1], try data_reader.readU32LenString());
        try m.consumed(data_packet.len);
    }

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_EOF, channel_ids[1]);
    try expectChannelEofForTest(&m, channel_ids[1]);
    try expectChannelEofForTest(&m, channel_ids[1]);
    try std.testing.expect(m.session.channel_table.findByLocalId(channel_ids[1]).?.eof_received);
    try std.testing.expect(!m.session.channel_table.findByLocalId(channel_ids[0]).?.eof_received);
    try m.clearEvent(.{ .ChannelEof = channel_ids[1] });
    try sendChannelDataForTest(&m, channel_ids[0], 100, 0xa0);

    try m.sendChannelClose(channel_ids[3]);
    const close_packet = try m.peek(Protocol.MaxSSHPacket);
    var close_reader = BufferReader.init(unencryptedPayload(close_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE), try close_reader.readU8());
    try std.testing.expectEqual(@as(u32, 103), try close_reader.readU32());
    try m.consumed(close_packet.len);

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_CLOSE, channel_ids[3]);
    try expectChannelClosedForTest(&m, channel_ids[3]);
    try std.testing.expect(m.session.channel_table.findByLocalId(channel_ids[3]) != null);
    try std.testing.expectEqual(@as(u32, runtime_channel_limit), m.session.channel_table.activeCount());
    try std.testing.expectError(
        IoError.cannotAcceptWrite,
        m.openDirectTcpipChannel("example.com", 443, "127.0.0.1", 60_000),
    );
    try m.clearEvent(.{ .ChannelClosed = channel_ids[3] });

    try std.testing.expect(m.session.channel_table.findByLocalId(channel_ids[3]) == null);
    try std.testing.expect(m.session.channel_table.findByLocalId(channel_ids[0]) != null);
    try std.testing.expect(m.session.channel_table.findByLocalId(channel_ids[1]) != null);
    try std.testing.expectEqual(@as(u32, runtime_channel_limit - 1), m.session.channel_table.activeCount());

    const replacement_id = try openConfirmedDirectTcpipForTest(&m, 203, 60_003);
    try std.testing.expectEqual(@as(u32, runtime_channel_limit), replacement_id);
    channel_ids[3] = replacement_id;
    try std.testing.expectEqual(@as(u32, runtime_channel_limit), m.session.channel_table.activeCount());
    try sendChannelDataForTest(&m, channel_ids[4], 104, 0xa4);

    for (channel_ids) |channel_id| {
        const chan = m.session.channel_table.findByLocalId(channel_id).?;
        const remote_id = chan.remote_id;
        try m.sendChannelClose(channel_id);
        const local_close = try m.peek(Protocol.MaxSSHPacket);
        var local_close_reader = BufferReader.init(unencryptedPayload(local_close));
        try std.testing.expectEqual(
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE),
            try local_close_reader.readU8(),
        );
        try std.testing.expectEqual(remote_id, try local_close_reader.readU32());
        try m.consumed(local_close.len);
        try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_CLOSE, channel_id);
        try expectChannelClosedForTest(&m, channel_id);
        try m.clearEvent(.{ .ChannelClosed = channel_id });
    }

    try std.testing.expectEqual(@as(u32, 0), m.session.channel_table.activeCount());
    try std.testing.expectEqual(SessionState.ChannelActive, m.session.sessionState);
    try std.testing.expect(m.session.user_authenticated);
    try std.testing.expect(!m.terminated);

    const reused_after_idle = try openConfirmedDirectTcpipForTest(&m, 300, 61_000);
    try std.testing.expectEqual(@as(u32, runtime_channel_limit + 1), reused_after_idle);
    try expectChannelData(&m, reused_after_idle, "after-zero-channel-idle");
}

test "manual ordinary channel read credit isolates blocked channels" {
    const limits = Sshz.ResourceLimits{
        .max_channels = 2,
        .initial_channel_window = 8,
        .max_channel_window = 32768,
        .channel_packet_size = 4,
        .max_peer_packet_size = 4096,
    };
    var prng = std.Random.DefaultPrng.init(43);
    var m = try SshzClient.initWithLimits(
        prng.random(),
        "testuser",
        std.testing.allocator,
        limits,
    );
    defer m.deinit();

    try m.setAutoSessionEnabled(false);
    try m.setAutoChannelReadCreditEnabled(false);
    m.session.encrypted = false;
    m.session.current_auth_method = .None;
    m.session.setSessionState(.AuthRsp);
    var auth_payload = [_]u8{@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS)};
    const auth_packet_len = buildUnencryptedPacket(&m.iobuf_rd, &auth_payload);
    try m.session.handlePacket(m.iobuf_rd[0..auth_packet_len], &m);
    try m.advance();
    try m.clearEvent(.Connected);

    const blocked_id = try openConfirmedDirectTcpipForTest(&m, 400, 62_000);
    const flowing_id = try openConfirmedDirectTcpipForTest(&m, 401, 62_001);
    const blocked = m.session.channel_table.findByLocalId(blocked_id).?;
    const flowing = m.session.channel_table.findByLocalId(flowing_id).?;
    try std.testing.expect(!blocked.automatic_read_credit);
    try std.testing.expect(!flowing.automatic_read_credit);
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        m.setAutoChannelReadCreditEnabled(true),
    );

    try expectChannelData(&m, blocked_id, "aaaa");
    try std.testing.expectEqual(ChannelState.DataRx, blocked.state);
    try expectChannelData(&m, blocked_id, "bbbb");
    try std.testing.expectEqual(@as(u32, 0), blocked.local_window);
    try std.testing.expectEqual(@as(u32, 8), blocked.delivered_uncredited);
    try std.testing.expectEqual(@as(u32, 0), blocked.pending_window_adjust);
    try std.testing.expectEqual(@as(usize, 0), m.wr_nbytes);
    for (m.iobuf_rd) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (m.iobuf_decompressed) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    try std.testing.expectError(
        error.InvalidChannelReadCredit,
        m.channelReadConsumed(blocked_id, 0),
    );
    try std.testing.expectError(
        error.ChannelReadCreditExceeded,
        m.channelReadConsumed(blocked_id, 9),
    );
    try std.testing.expectEqual(@as(u32, 8), blocked.delivered_uncredited);
    try std.testing.expectEqual(@as(u32, 0), blocked.pending_window_adjust);

    for (0..6) |cycle| {
        const byte: u8 = @intCast('c' + cycle);
        const data = [4]u8{ byte, byte, byte, byte };
        try expectChannelData(&m, flowing_id, &data);
        try std.testing.expectEqual(@as(u32, 4), flowing.delivered_uncredited);
        try std.testing.expectEqual(@as(u32, 4), flowing.local_window);
        try std.testing.expectEqual(@as(u32, 0), blocked.local_window);
        try std.testing.expectEqual(@as(u32, 8), blocked.delivered_uncredited);

        if (cycle == 0) {
            try m.channelReadConsumed(flowing_id, 2);
            try expectWindowAdjustForTest(&m, flowing.remote_id, 2);
            try std.testing.expectEqual(@as(u32, 2), flowing.delivered_uncredited);
            try std.testing.expectEqual(@as(u32, 6), flowing.local_window);
            try m.channelReadConsumed(flowing_id, 2);
            try expectWindowAdjustForTest(&m, flowing.remote_id, 2);
        } else {
            try m.channelReadConsumed(flowing_id, 4);
            try expectWindowAdjustForTest(&m, flowing.remote_id, 4);
        }
        try std.testing.expectEqual(@as(u32, 0), flowing.delivered_uncredited);
        try std.testing.expectEqual(@as(u32, 8), flowing.local_window);
        try std.testing.expectEqual(@as(u32, 0), blocked.local_window);
    }

    try std.testing.expectError(
        error.ChannelReadCreditExceeded,
        m.channelReadConsumed(flowing_id, 1),
    );
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        m.channelReadConsumed(9999, 1),
    );

    try m.sendChannelClose(flowing_id);
    const close_packet = try m.peek(Protocol.MaxSSHPacket);
    try m.consumed(close_packet.len);
    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_CLOSE, flowing_id);
    try expectChannelClosedForTest(&m, flowing_id);
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        m.channelReadConsumed(flowing_id, 1),
    );
    try m.clearEvent(.{ .ChannelClosed = flowing_id });
}

test "manual channel window adjusts are round-robin with deferred output" {
    const limits = Sshz.ResourceLimits{
        .max_channels = 2,
        .initial_channel_window = 8,
        .max_channel_window = 100,
        .channel_packet_size = 4,
        .max_peer_packet_size = 100,
    };
    var prng = std.Random.DefaultPrng.init(44);
    var m = try SshzClient.initWithLimits(
        prng.random(),
        "testuser",
        std.testing.allocator,
        limits,
    );
    defer m.deinit();

    const first = m.session.channel_table.allocChannel(500, 100, 100).?;
    first.state = .DataRx;
    first.automatic_read_credit = false;
    first.local_window = 4;
    first.delivered_uncredited = 4;
    try first.queueReadCredit(4);
    first.write_buf[0] = 'x';
    first.write_buf_nbytes = 1;

    const second = m.session.channel_table.allocChannel(501, 100, 100).?;
    second.state = .DataRx;
    second.automatic_read_credit = false;
    second.local_window = 4;
    second.delivered_uncredited = 4;
    try second.queueReadCredit(4);

    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 1, .ReadPktHdr);

    try std.testing.expect(try m.session.dispatchDeferredChannelWrite(&m));
    try expectWindowAdjustForTest(&m, second.remote_id, 4);
    try expectWindowAdjustForTest(&m, first.remote_id, 4);

    const data_packet = try m.peek(Protocol.MaxSSHPacket);
    var data_reader = BufferReader.init(unencryptedPayload(data_packet));
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA),
        try data_reader.readU8(),
    );
    try std.testing.expectEqual(first.remote_id, try data_reader.readU32());
    try std.testing.expectEqualStrings("x", try data_reader.readU32LenString());
    try m.consumed(data_packet.len);
    try std.testing.expectEqual(@as(u32, 8), first.local_window);
    try std.testing.expectEqual(@as(u32, 8), second.local_window);
}

test "manual read credit flushes after unrelated write during packet header read" {
    const limits = Sshz.ResourceLimits{
        .max_channels = 1,
        .initial_channel_window = 8,
        .max_channel_window = 100,
        .channel_packet_size = 4,
        .max_peer_packet_size = 100,
    };
    var prng = std.Random.DefaultPrng.init(45);
    var m = try SshzClient.initWithLimits(
        prng.random(),
        "testuser",
        std.testing.allocator,
        limits,
    );
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(502, 100, 100).?;
    chan.state = .DataRx;
    chan.automatic_read_credit = false;
    chan.local_window = 4;
    chan.delivered_uncredited = 4;

    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(
        0,
        Protocol.sizeof_PktHdr,
        .{ .ReadPktBody = m.iobuf_rd[0..Protocol.sizeof_PktHdr] },
    );

    try m.session.queueChannelReply(503, false);
    try std.testing.expect(try m.session.dispatchDeferredChannelWrite(&m));
    const reply = try m.peek(Protocol.MaxSSHPacket);
    var reply_reader = BufferReader.init(unencryptedPayload(reply));
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_FAILURE),
        try reply_reader.readU8(),
    );
    try std.testing.expectEqual(@as(u32, 503), try reply_reader.readU32());

    try m.channelReadConsumed(chan.local_id, 4);
    try std.testing.expectEqual(@as(u32, 4), chan.pending_window_adjust);
    try std.testing.expectEqual(@as(u32, 4), chan.local_window);

    try m.consumed(reply.len);
    try expectWindowAdjustForTest(&m, chan.remote_id, 4);
    try std.testing.expectEqual(@as(u32, 0), chan.pending_window_adjust);
    try std.testing.expectEqual(@as(u32, 8), chan.local_window);
    try std.testing.expect(m.iostate_rd != .Idle);
}

test "disabled auto session rejects session-dependent configuration" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.setAutoSessionEnabled(false);
    try std.testing.expectError(error.UnexpectedResponse, m.enableAgentForwarding());
    try std.testing.expectError(error.UnexpectedResponse, m.setAutoExecCommand("true"));
    try std.testing.expectError(
        error.UnexpectedResponse,
        m.setAutoPty("xterm-color", 80, 24, 640, 480),
    );
}

test "configured pty guards auto session and failClosed clears ownership" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    try session.setAutoPty("xterm-color", 80, 24, 640, 480);
    try std.testing.expect(session.auto_pty_requested);
    try std.testing.expectError(error.UnexpectedResponse, session.setAutoSessionEnabled(false));

    session.failClosed();
    try std.testing.expect(!session.auto_pty_requested);
    try std.testing.expectEqual(@as(?[]u8, null), session.auto_pty_term);
}

test "none rejection falls back through missing key to password" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.try_none_auth = true;
    m.session.current_auth_method = .None;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = 1;
    m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.None)] = 1;
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    const pkt_len = try buildAuthFailurePacket(&m, "publickey,password,keyboard-interactive", false);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const key_event = try m.getNextEvent();
    const key_code = switch (key_event) {
        .Event => |code| code,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(key_code == .GetPrivateKey);
    try m.clearEvent(key_code);

    const password_event = try m.getNextEvent();
    const password_code = switch (password_event) {
        .Event => |code| code,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(password_code == .GetAuthPassphrase);
    try m.setAuthPassphrase("secret");
    try m.clearEvent(password_code);

    try expectQueuedAuthMethodStarted(&m, .Password);
}

test "public key rejection with partial success falls back to password" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    try m.setAuthPassphrase("secret");
    m.session.current_auth_method = .PublicKey;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = 1;
    m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.PublicKey)] = 1;
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    const pkt_len = try buildAuthFailurePacket(&m, "password,keyboard-interactive", true);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try expectQueuedAuthMethodStarted(&m, .Password);
}

test "partial success starts a new stage and permits public key again" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    try m.setPrivateKey(@import("privkey.zig").testkey_valid);
    m.session.current_auth_method = .PublicKey;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = 1;
    m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.PublicKey)] = 1;
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    const pkt_len = try buildAuthFailurePacket(&m, "publickey", true);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try expectQueuedAuthMethodStarted(&m, .PublicKey);
    try std.testing.expectEqual(@as(u8, 1), m.session.auth_stage);
    try std.testing.expectEqual(@as(u8, 2), m.session.auth_attempts_total);
    try std.testing.expectEqual(
        @as(u8, 1),
        m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.PublicKey)],
    );
}

test "none is not retried after partial success" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.try_none_auth = true;
    try m.setAuthPassphrase("secret");
    m.session.current_auth_method = .None;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = 1;
    m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.None)] = 1;
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    const pkt_len = try buildAuthFailurePacket(&m, "none,password", true);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try expectQueuedAuthMethodStarted(&m, .Password);
    try std.testing.expectEqual(@as(u8, 1), m.session.auth_stage);
    try std.testing.expectEqual(@as(u8, 2), m.session.auth_attempts_total);
    try std.testing.expectEqual(
        @as(u8, 0),
        m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.None)],
    );
}

test "partial success cannot exceed total authentication request cap" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.current_auth_method = .PublicKey;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = MaxAuthAttemptsTotal;
    m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.PublicKey)] = 1;
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    const pkt_len = try buildAuthFailurePacket(&m, "publickey", true);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .EndSession => |reason| switch (reason) {
                .AuthFailure => |failure| {
                    try std.testing.expect(failure.partial_success);
                    try std.testing.expect(failure.hasMethod(.PublicKey));
                    try std.testing.expectEqual(@as(u8, 0), failure.auth_stage);
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(MaxAuthAttemptsTotal, m.session.auth_attempts_total);
    try std.testing.expectEqual(@as(u8, 1), m.session.auth_stage);
}

test "password rejection falls back to keyboard interactive" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.current_auth_method = .Password;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = 1;
    m.session.auth_stage_attempts_by_method[@intFromEnum(AuthMethod.Password)] = 1;
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    const pkt_len = try buildAuthFailurePacket(&m, "keyboard-interactive", false);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try expectQueuedAuthMethodStarted(&m, .KeyboardInteractive);
}

test "auth failure preserves unsupported methods and partial success" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.current_auth_method = .KeyboardInteractive;
    m.session.setSessionState(.AuthMethodQueued);
    m.session.auth_attempts_total = MaxAuthAttemptsTotal;
    m.session.auth_stage_attempts_by_method = .{1} ** 4;
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;

    const methods = "gssapi-with-mic,webauthn@vendor";
    const pkt_len = try buildAuthFailurePacket(&m, methods, true);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    @memset(&m.iobuf_rd, 0);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .EndSession => |reason| switch (reason) {
                .AuthFailure => |failure| {
                    try std.testing.expectEqual(AuthMethod.KeyboardInteractive, failure.attempted_method);
                    try std.testing.expectEqualStrings(methods, failure.unsupportedMethodNames());
                    try std.testing.expectEqual(@as(usize, 0), failure.supportedMethods().len);
                    try std.testing.expect(failure.partial_success);
                    try std.testing.expectEqual(@as(u8, 0), failure.auth_stage);
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "default authentication still starts with credentials" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setSessionState(.AuthStart);
    m.session.setIoSessionState(.Idle);
    try m.advance();
    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| try std.testing.expect(code == .GetPrivateKey),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!m.session.try_none_auth);
    try std.testing.expectEqual(@as(u8, 0), m.session.auth_attempts_total);
}

test "rekey hashes retained exact client and server versions" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    session.clearAndFreeOptional(&session.client_version);
    session.client_version = try std.testing.allocator.dupe(u8, "SSH-2.0-exact_client comment");
    try session.setPeerProtocolVersion("SSH-1.99-exact_server comment");
    session.resetKexHasherForRekey();

    var expected_hasher = Hasher(Protocol.hash_algo).init();
    expected_hasher.writeU32LenString("SSH-2.0-exact_client comment");
    expected_hasher.writeU32LenString("SSH-1.99-exact_server comment");
    var expected: [Protocol.hash_algo.digest_length]u8 = undefined;
    expected_hasher.final(&expected, null);
    var actual: [Protocol.hash_algo.digest_length]u8 = undefined;
    session.kex_hasher.final(&actual, null);

    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "client rekey cannot switch the accepted host identity" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();
    session.hostkey_ks = try std.testing.allocator.dupe(u8, "accepted-host-key");
    session.is_rekeying = true;

    try session.bindVerifiedHostKey("accepted-host-key");
    try std.testing.expectError(
        IoError.HostKeyChanged,
        session.bindVerifiedHostKey("different-host-key"),
    );
    try std.testing.expectEqualStrings("accepted-host-key", session.hostkey_ks.?);
}

test "server initiated client rekey sends and hashes client KEXINIT before server KEXINIT" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();
    try m.session.setPeerProtocolVersion("SSH-2.0-test_server");

    var server_payload_buf: [512]u8 = undefined;
    var server_payload = BufferWriter.init(&server_payload_buf, 0);
    try writeKexInitPayload(&server_payload);
    const server_packet_len = buildUnencryptedPacket(&m.iobuf_rd, server_payload.active());
    m.session.session_id_established = true;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);

    try m.session.handlePacket(m.iobuf_rd[0..server_packet_len], &m);
    try std.testing.expect(m.session.is_rekeying);
    try std.testing.expectEqual(SessionState.KexInitWrite, m.session.sessionState);
    try std.testing.expectEqual(Protocol.KexHashOrder.V_S, m.session.kex_hash_order);
    try std.testing.expectEqualStrings(server_payload.active(), m.session.pending_server_kexinit.?);

    try m.session.advanceSession(&m);
    const client_packet = try m.peek(Protocol.MaxSSHPacket);
    const client_payload = unencryptedPayload(client_packet);
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT), client_payload[0]);
    try std.testing.expectEqual(SessionState.EcdhInitWrite, m.session.sessionState);
    try std.testing.expectEqual(Protocol.KexHashOrder.I_S, m.session.kex_hash_order);
    try std.testing.expect(m.session.pending_server_kexinit == null);

    var expected_hasher = Hasher(Protocol.hash_algo).init();
    expected_hasher.writeU32LenString(m.session.client_version.?);
    expected_hasher.writeU32LenString(m.session.server_version.?);
    expected_hasher.writeU32LenString(client_payload);
    expected_hasher.writeU32LenString(server_payload.active());
    var expected: [Protocol.hash_algo.digest_length]u8 = undefined;
    expected_hasher.final(&expected, null);
    var actual: [Protocol.hash_algo.digest_length]u8 = undefined;
    m.session.kex_hasher.final(&actual, null);
    try std.testing.expectEqualSlices(u8, &expected, &actual);

    try m.consumed(client_packet.len);
    const ecdh_packet = try m.peek(Protocol.MaxSSHPacket);
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT),
        unencryptedPayload(ecdh_packet)[0],
    );
}

test "simultaneous client local and server rekey uses one exact KEXINIT pair" {
    var prng = std.Random.DefaultPrng.init(142);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();
    try m.session.setPeerProtocolVersion("SSH-2.0-test_server");
    m.session.session_id_established = true;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    m.session.encrypted = true;
    m.session.inbound_encrypted = true;
    m.session.startLocalRekey();
    m.session.encrypted = false;
    m.session.inbound_encrypted = false;

    try m.session.advanceSession(&m);
    const local_packet = try m.peek(Protocol.MaxSSHPacket);
    const local_payload = unencryptedPayload(local_packet);
    var local_payload_copy: [512]u8 = undefined;
    @memcpy(local_payload_copy[0..local_payload.len], local_payload);
    const local_payload_len = local_payload.len;
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT), local_payload[0]);
    try std.testing.expectEqual(SessionState.KexInitRead, m.session.sessionState);
    try m.consumed(local_packet.len);

    var peer_payload_buf: [512]u8 = undefined;
    var peer_payload = BufferWriter.init(&peer_payload_buf, 0);
    try writeKexInitPayload(&peer_payload);
    const peer_packet_len = buildUnencryptedPacket(&m.iobuf_rd, peer_payload.active());
    try m.session.handlePacket(m.iobuf_rd[0..peer_packet_len], &m);

    try std.testing.expect(m.session.is_rekeying);
    try std.testing.expectEqual(SessionState.EcdhInitWrite, m.session.sessionState);
    try std.testing.expect(m.session.pending_server_kexinit == null);
    try std.testing.expectEqual(Protocol.KexHashOrder.I_S, m.session.kex_hash_order);

    var expected_hasher = Hasher(Protocol.hash_algo).init();
    expected_hasher.writeU32LenString(m.session.client_version.?);
    expected_hasher.writeU32LenString(m.session.server_version.?);
    expected_hasher.writeU32LenString(local_payload_copy[0..local_payload_len]);
    expected_hasher.writeU32LenString(peer_payload.active());
    var expected: [Protocol.hash_algo.digest_length]u8 = undefined;
    expected_hasher.final(&expected, null);
    var actual: [Protocol.hash_algo.digest_length]u8 = undefined;
    m.session.kex_hasher.final(&actual, null);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "client rekey gates deferred channel traffic until NEWKEYS completes" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();
    try m.session.setPeerProtocolVersion("SSH-2.0-test_server");

    const channel_a = m.session.channel_table.allocChannel(10, 2000, 1000).?;
    channel_a.state = .DataRx;
    const channel_b = m.session.channel_table.allocChannel(20, 1000, 1000).?;
    channel_b.state = .DataRx;
    for (channel_a.write_buf[0..2000], 0..) |*byte, index| byte.* = @truncate(index);
    m.session.session_id_established = true;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 1, .ReadPktHdr);
    try m.channelWriteComplete(channel_a.local_id, 2000);
    try m.sendChannelEof(channel_b.local_id);

    var server_payload_buf: [512]u8 = undefined;
    var server_payload = BufferWriter.init(&server_payload_buf, 0);
    try writeKexInitPayload(&server_payload);
    const server_packet_len = buildUnencryptedPacket(&m.iobuf_rd, server_payload.active());
    m.iostate_rd = .Idle;
    m.session.setIoSessionState(.{ .ReadPktCompletion = m.iobuf_rd[0..server_packet_len] });

    var first_fragment: [1000]u8 = undefined;
    _ = try consumeProducedChannelDataForTest(&m, &first_fragment, 0);
    try std.testing.expect(m.session.is_rekeying);
    try std.testing.expectEqual(@as(usize, 1000), channel_a.write_buf_nbytes);
    try std.testing.expect(channel_b.eof_pending);

    const client_kexinit = try m.peek(Protocol.MaxSSHPacket);
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT),
        unencryptedPayload(client_kexinit)[0],
    );
    try m.consumed(client_kexinit.len);
    const ecdh_init = try m.peek(Protocol.MaxSSHPacket);
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT),
        unencryptedPayload(ecdh_init)[0],
    );
    try m.consumed(ecdh_init.len);

    m.iostate_rd = .Idle;
    m.session.session_id = .{0x11} ** Protocol.hash_algo.digest_length;
    m.session.shared_secret_k = .{0x22} ** Protocol.kex_algo.shared_length;
    m.session.negotiated_compression_c2s = .None;
    m.session.negotiated_compression_s2c = .None;
    try m.session.installExchangeKeys(.{0x33} ** Protocol.hash_algo.digest_length);
    const new_c2s_key = m.session.pending_c2s_keys.?.key;
    m.session.setSessionState(.NewKeysWrite);
    m.session.setIoSessionState(.Idle);
    try m.session.advanceSession(&m);

    const newkeys = try m.peek(Protocol.MaxSSHPacket);
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS),
        unencryptedPayload(newkeys)[0],
    );
    try std.testing.expectEqual(@as(usize, 1000), channel_a.write_buf_nbytes);
    try std.testing.expect(channel_b.eof_pending);
    try m.consumed(newkeys.len);

    try std.testing.expectEqualSlices(u8, &new_c2s_key, &m.session.keydata.c2s.key);
    var resumed_data = try m.peek(Protocol.MaxSSHPacket);
    if (channel_a.tx_in_flight_len == 0) {
        try std.testing.expectEqual(ChannelControl.Eof, channel_b.control_in_flight.?);
        try m.consumed(resumed_data.len);
        resumed_data = try m.peek(Protocol.MaxSSHPacket);
    }
    try std.testing.expectEqual(@as(usize, 1000), channel_a.tx_in_flight_len);
    try m.consumed(resumed_data.len);
    try std.testing.expectEqual(@as(usize, 0), channel_a.write_buf_nbytes);
    try std.testing.expect(channel_b.eof_sent);
}

test "client rekey preserves initial session id for key derivation" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    const original_session_id: [Protocol.hash_algo.digest_length]u8 = .{0x11} ** Protocol.hash_algo.digest_length;
    const rekey_hash: [Protocol.hash_algo.digest_length]u8 = .{0x33} ** Protocol.hash_algo.digest_length;
    const rekey_secret: [Protocol.kex_algo.shared_length]u8 = .{0x22} ** Protocol.kex_algo.shared_length;
    session.session_id = original_session_id;
    session.shared_secret_k = rekey_secret;
    session.is_rekeying = true;
    session.session_id_established = true;

    var expected = Protocol.KeyDataBi.init();
    defer expected.clear();
    try expected.genKeys(rekey_hash, rekey_secret, original_session_id);
    var wrong = Protocol.KeyDataBi.init();
    defer wrong.clear();
    try wrong.genKeys(rekey_hash, rekey_secret, rekey_hash);

    try session.installExchangeKeys(rekey_hash);

    const pending_c2s = &session.pending_c2s_keys.?;
    const pending_s2c = &session.pending_s2c_keys.?;
    try std.testing.expectEqualSlices(u8, &original_session_id, &session.session_id);
    try std.testing.expectEqualSlices(u8, &expected.c2s.iv, &pending_c2s.iv);
    try std.testing.expectEqualSlices(u8, &expected.c2s.key, &pending_c2s.key);
    try std.testing.expectEqualSlices(u8, &expected.c2s.mackey, &pending_c2s.mackey);
    try std.testing.expectEqualSlices(u8, &expected.s2c.iv, &pending_s2c.iv);
    try std.testing.expectEqualSlices(u8, &expected.s2c.key, &pending_s2c.key);
    try std.testing.expectEqualSlices(u8, &expected.s2c.mackey, &pending_s2c.mackey);
    try std.testing.expect(!std.mem.eql(u8, &wrong.c2s.key, &pending_c2s.key));
}

test "client rekey activates inbound and outbound keys at NEWKEYS boundaries" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const session_id: [Protocol.hash_algo.digest_length]u8 = .{0x10} ** Protocol.hash_algo.digest_length;
    const old_hash: [Protocol.hash_algo.digest_length]u8 = .{0x20} ** Protocol.hash_algo.digest_length;
    const old_secret: [Protocol.kex_algo.shared_length]u8 = .{0x30} ** Protocol.kex_algo.shared_length;
    const new_hash: [Protocol.hash_algo.digest_length]u8 = .{0x40} ** Protocol.hash_algo.digest_length;
    const new_secret: [Protocol.kex_algo.shared_length]u8 = .{0x50} ** Protocol.kex_algo.shared_length;
    m.session.session_id = session_id;
    try m.session.keydata.genKeys(old_hash, old_secret, session_id);
    m.session.keydata.c2s.epoch = 3;
    m.session.keydata.c2s.encrypted_bytes = 700;
    m.session.keydata.c2s.encrypted_packets = 7;
    m.session.keydata.s2c.epoch = 4;
    m.session.keydata.s2c.encrypted_bytes = 800;
    m.session.keydata.s2c.encrypted_packets = 8;
    m.session.encrypted = true;
    m.session.inbound_encrypted = true;
    try m.initializeDeadlines(100);
    m.session.is_rekeying = true;
    m.session.session_id_established = true;
    m.session.shared_secret_k = new_secret;
    try m.session.installExchangeKeys(new_hash);

    var old_c2s = m.session.keydata.c2s;
    var old_s2c = m.session.keydata.s2c;
    defer old_s2c.clear();
    const new_c2s_key = m.session.pending_c2s_keys.?.key;
    const new_s2c_key = m.session.pending_s2c_keys.?.key;

    var server_packet_buf: [Protocol.MaxSSHPacket]u8 = undefined;
    var server_packet = BufferWriter.init(&server_packet_buf, Protocol.sizeof_PktHdr);
    try server_packet.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
    var server_prng = std.Random.DefaultPrng.init(99);
    var server_rand = server_prng.random();
    const wrapped_server_newkeys = try Protocol.wrapPkt(
        &server_rand,
        true,
        &old_s2c,
        &server_packet,
        &server_packet_buf,
    );
    @memcpy(m.iobuf_rd[0..wrapped_server_newkeys.len], wrapped_server_newkeys);
    try decryptFirstBlockForTest(m.iobuf_rd[0..wrapped_server_newkeys.len], &m.session.keydata.s2c);
    m.session.setSessionState(.NewKeysRead);
    try m.session.handlePacket(m.iobuf_rd[0..wrapped_server_newkeys.len], &m);

    try std.testing.expectEqualSlices(u8, &old_c2s.key, &m.session.keydata.c2s.key);
    try std.testing.expectEqualSlices(u8, &new_s2c_key, &m.session.keydata.s2c.key);
    try std.testing.expectEqual(@as(u32, 1), m.session.keydata.s2c.seq);
    try std.testing.expectEqual(@as(u64, 5), m.session.keydata.s2c.epoch);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.s2c.encrypted_bytes);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.s2c.encrypted_packets);
    try std.testing.expectEqual(@as(?u64, 100), m.session.keydata.s2c.activated_at_monotonic_tick);
    try std.testing.expectEqual(@as(u64, 3), m.session.keydata.c2s.epoch);
    try std.testing.expectEqual(@as(u64, 7), m.session.keydata.c2s.encrypted_packets);
    try std.testing.expect(m.session.pending_c2s_keys != null);
    try std.testing.expect(m.session.pending_s2c_keys == null);

    try m.session.advanceSession(&m);
    const client_newkeys = try m.peek(Protocol.MaxSSHPacket);
    try std.testing.expectEqualSlices(u8, &new_c2s_key, &m.session.keydata.c2s.key);
    try std.testing.expectEqual(@as(u32, 1), m.session.keydata.c2s.seq);
    try std.testing.expectEqual(@as(u64, 4), m.session.keydata.c2s.epoch);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.c2s.encrypted_bytes);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.c2s.encrypted_packets);
    try std.testing.expectEqual(@as(?u64, 100), m.session.keydata.c2s.activated_at_monotonic_tick);
    try std.testing.expect(m.session.pending_c2s_keys == null);

    var verifier_prng = std.Random.DefaultPrng.init(7);
    var verifier = try Sshz.SshzServer.init(
        verifier_prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
    );
    defer verifier.deinit();
    verifier.session.keydata.c2s.clear();
    verifier.session.keydata.c2s = old_c2s;
    old_c2s = .{ .seq = 0 };
    verifier.session.inbound_encrypted = true;
    @memcpy(verifier.iobuf_rd[0..client_newkeys.len], client_newkeys);
    try decryptFirstBlockForTest(verifier.iobuf_rd[0..client_newkeys.len], &verifier.session.keydata.c2s);
    var rdr = try verifier.getRecvBuffer(
        verifier.iobuf_rd[0..client_newkeys.len],
        &verifier.session.keydata.c2s,
    );
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS), try rdr.readU8());
}

test "handlePacket: SSH_MSG_IGNORE is silently consumed" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_buf: [1]u8 = .{@intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE)};
    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, &payload_buf);
    m.session.encrypted = false;
    m.session.setIoSessionState(.ReadPktHdr);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
}

test "openSessionChannel writes channel open for new raw session channel" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);

    const channel_id = try m.openSessionChannel();
    try std.testing.expectEqual(@as(u32, 0), channel_id);
    try std.testing.expectEqual(SessionState.ChannelOpenRsp, m.session.sessionState);

    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ClientChannelOpenMode.RawSession, chan.client_open_mode);
    try std.testing.expectEqual(ChannelType.Session, chan.channel_type);
    try std.testing.expectEqual(ChannelState.OpenWrite, chan.state);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try rdr.readU8());
    try std.testing.expectEqualStrings("session", try rdr.readU32LenString());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
    try std.testing.expectEqual(Sshz.default_channel_window, try rdr.readU32());
    try std.testing.expectEqual(Protocol.MaxChannelDataLen, try rdr.readU32());
}

test "openDirectTcpipChannel writes direct-tcpip open payload" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);

    const channel_id = try m.openDirectTcpipChannel("example.com", 443, "127.0.0.1", 55555);
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ChannelType.DirectTcpip, chan.channel_type);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try rdr.readU8());
    try std.testing.expectEqualStrings("direct-tcpip", try rdr.readU32LenString());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
    try std.testing.expectEqual(Sshz.default_channel_window, try rdr.readU32());
    try std.testing.expectEqual(Protocol.MaxChannelDataLen, try rdr.readU32());
    try std.testing.expectEqualStrings("example.com", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 443), try rdr.readU32());
    try std.testing.expectEqualStrings("127.0.0.1", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 55555), try rdr.readU32());
}

test "requestRemoteForward writes tcpip-forward global request" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);

    try m.requestRemoteForward("127.0.0.1", 0);
    try std.testing.expect(m.session.pending_global_request != null);
    try std.testing.expectError(
        IoError.ResourceLimitExceeded,
        m.cancelRemoteForward("127.0.0.1", 0),
    );

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST), try rdr.readU8());
    try std.testing.expectEqualStrings("tcpip-forward", try rdr.readU32LenString());
    try std.testing.expect(try rdr.readBoolean());
    try std.testing.expectEqualStrings("127.0.0.1", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 0), try rdr.readU32());
}

test "cancelRemoteForward writes cancel-tcpip-forward global request" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);

    try m.cancelRemoteForward("127.0.0.1", 2200);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST), try rdr.readU8());
    try std.testing.expectEqualStrings("cancel-tcpip-forward", try rdr.readU32LenString());
    try std.testing.expect(try rdr.readBoolean());
    try std.testing.expectEqualStrings("127.0.0.1", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 2200), try rdr.readU32());
}

fn keepaliveTestClient(random: std.Random) !SshzClient {
    var client = try SshzClient.init(random, "test", std.testing.allocator);
    client.session.user_authenticated = true;
    client.session.setSessionState(.ChannelActive);
    client.session.setIoSessionState(.ReadPktHdr);
    return client;
}

fn feedKeepaliveTestPayload(client: *SshzClient, payload: []const u8) !void {
    var packet: [256]u8 = undefined;
    const len = buildUnencryptedPacket(&packet, payload);
    try feedKeepaliveTestBytes(client, packet[0..len]);
}

fn feedKeepaliveTestBytes(client: *SshzClient, packet: []const u8) !void {
    var offset: usize = 0;
    while (offset < packet.len) {
        const available = switch (try client.getNextEvent()) {
            .ReadyToConsume => |n| n,
            .ReadyToConsumeAndProduce => |counts| counts.consume,
            else => return error.TestUnexpectedResult,
        };
        const count = @min(available, packet.len - offset);
        try client.write(packet[offset..][0..count]);
        offset += count;
    }
}

fn consumeKeepaliveTestPacket(client: *SshzClient) !void {
    const bytes = try client.peek(Protocol.MaxSSHPacket);
    try client.consumed(bytes.len);
}

test "keepalive is opt-in and acknowledges both reply types with owned tokens" {
    for ([_]Sshz.KeepaliveReply{ .Success, .Failure }) |reply| {
        var prng = std.Random.DefaultPrng.init(43);
        var client = try keepaliveTestClient(prng.random());
        defer client.deinit();
        try std.testing.expect((try client.getNextEvent()) == .ReadyToConsume);

        const token = try client.requestKeepalive();
        try std.testing.expectEqual(Sshz.KeepaliveTransmission.Emitting, (try client.keepaliveStatus(token)).transmission);
        try std.testing.expectError(IoError.NotReady, client.markKeepaliveFlushed(token));
        try std.testing.expectError(IoError.NotReady, client.clearKeepalive(token));
        var rdr = BufferReader.init(unencryptedPayload(try client.peek(Protocol.MaxSSHPacket)));
        try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST), try rdr.readU8());
        try std.testing.expectEqualStrings("keepalive@openssh.com", try rdr.readU32LenString());
        try std.testing.expect(try rdr.readBoolean());
        try std.testing.expectEqual(rdr.payload.len, rdr.off);

        try consumeKeepaliveTestPacket(&client);
        var status = try client.keepaliveStatus(token);
        try std.testing.expectEqual(Sshz.KeepaliveTransmission.HandedToTransport, status.transmission);
        try std.testing.expect(!status.transport_flushed);
        try std.testing.expect(status.outcome == .Pending);
        try client.markKeepaliveFlushed(token);
        try client.markKeepaliveFlushed(token);
        try feedKeepaliveTestPayload(&client, &.{@intFromEnum(switch (reply) {
            .Success => Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS,
            .Failure => Protocol.MsgId.SSH_MSG_REQUEST_FAILURE,
        })});
        status = try client.keepaliveStatus(token);
        try std.testing.expect(status.transport_flushed);
        try std.testing.expectEqual(reply, status.outcome.Acknowledged);
        try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
        try client.cancelKeepalive(token);
        try std.testing.expectEqualDeep(status, try client.keepaliveStatus(token));
        try client.clearKeepalive(token);
        const next_token = try client.requestKeepalive();
        try std.testing.expect(next_token.id > token.id);
        try std.testing.expectError(IoError.InvalidKeepaliveToken, client.keepaliveStatus(token));
        try std.testing.expectError(IoError.InvalidKeepaliveToken, client.markKeepaliveFlushed(token));
        try std.testing.expectError(IoError.InvalidKeepaliveToken, client.cancelKeepalive(token));
        try std.testing.expectError(IoError.InvalidKeepaliveToken, client.clearKeepalive(token));
        client.deinit();
        try std.testing.expectEqual(reply, status.outcome.Acknowledged);
        try std.testing.expectEqual(token.id, status.token.id);
    }
}

test "keepalive distinguishes queued partial emission and explicit transport flush" {
    var prng = std.Random.DefaultPrng.init(44);
    var client = try keepaliveTestClient(prng.random());
    defer client.deinit();
    _ = try client.getNextEvent();
    @memcpy(client.iobuf_wr[0..5], "prior");
    try client.requestWrite(client.iobuf_wr[0..5], .WriteCompletePreserveState);

    const token = try client.requestKeepalive();
    try std.testing.expectEqual(Sshz.KeepaliveTransmission.Queued, (try client.keepaliveStatus(token)).transmission);
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
    try std.testing.expectError(IoError.NotReady, client.markKeepaliveFlushed(token));
    try client.consumed(4);
    try std.testing.expectEqual(Sshz.KeepaliveTransmission.Queued, (try client.keepaliveStatus(token)).transmission);
    try std.testing.expectEqualStrings("r", try client.peek(1));
    try client.consumed(1);

    const total = (try client.peek(Protocol.MaxSSHPacket)).len;
    try std.testing.expectEqual(@as(usize, 1), (try client.peek(1)).len);
    try std.testing.expectEqual(@as(usize, 0), (try client.peek(0)).len);
    try client.consumed(0);
    try std.testing.expectError(IoError.notEnoughData, client.consumed(total + 1));
    for (0..total - 1) |i| {
        try client.consumed(1);
        const status = try client.keepaliveStatus(token);
        try std.testing.expectEqual(Sshz.KeepaliveTransmission.Emitting, status.transmission);
        try std.testing.expect(!status.transport_flushed);
        const next = try client.getNextEvent();
        try std.testing.expectEqual(total - i - 1, next.ReadyToConsumeAndProduce.produce);
    }
    try client.consumed(1);
    try std.testing.expectEqual(Sshz.KeepaliveTransmission.HandedToTransport, (try client.keepaliveStatus(token)).transmission);
    // consumed may mean a buffering adapter accepted the bytes, not a send.
    try std.testing.expect(!(try client.keepaliveStatus(token)).transport_flushed);
    try client.markKeepaliveFlushed(token);
    try std.testing.expect((try client.keepaliveStatus(token)).transport_flushed);
}

test "keepalive and forwarding share one ordered global-request slot" {
    var prng = std.Random.DefaultPrng.init(45);
    var client = try keepaliveTestClient(prng.random());
    defer client.deinit();
    try client.requestRemoteForward("localhost", 0);
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
    try consumeKeepaliveTestPacket(&client);
    try feedKeepaliveTestPayload(&client, &.{ @intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS), 0, 0, 8, 174 });
    const forward_event = (try client.getNextEvent()).Event;
    try std.testing.expectEqualStrings("localhost", forward_event.TcpipForwardSuccess.bind_address);
    try std.testing.expectEqual(@as(u32, 2222), forward_event.TcpipForwardSuccess.bound_port);
    // Queueing a probe must not overwrite a borrowed forwarding event.
    const token = try client.requestKeepalive();
    try std.testing.expectEqual(Sshz.KeepaliveTransmission.Queued, (try client.keepaliveStatus(token)).transmission);
    try std.testing.expectEqualStrings("localhost", forward_event.TcpipForwardSuccess.bind_address);
    try client.clearEvent(forward_event);
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestRemoteForward("localhost", 22));
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.cancelRemoteForward("localhost", 2222));
    try consumeKeepaliveTestPacket(&client);
    try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE)});
    try std.testing.expectEqual(Sshz.KeepaliveReply.Failure, (try client.keepaliveStatus(token)).outcome.Acknowledged);

    // Forwarding is independent of retention of a completed keepalive result.
    try client.cancelRemoteForward("localhost", 2222);
    try consumeKeepaliveTestPacket(&client);
    try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS)});
    const cancel_event = (try client.getNextEvent()).Event;
    try std.testing.expectEqual(@as(u32, 2222), cancel_event.CancelTcpipForwardSuccess.bind_port);
    try client.clearEvent(cancel_event);
    try std.testing.expectEqual(Sshz.KeepaliveReply.Failure, (try client.keepaliveStatus(token)).outcome.Acknowledged);
}

test "cancelled framed keepalive retains late-reply slot even after result release" {
    for ([_]usize{ 0, 1, std.math.maxInt(usize) }) |consumed| {
        var prng = std.Random.DefaultPrng.init(46);
        var client = try keepaliveTestClient(prng.random());
        defer client.deinit();
        const token = try client.requestKeepalive();
        const packet_len = (try client.peek(Protocol.MaxSSHPacket)).len;
        try client.consumed(@min(consumed, packet_len));
        try client.cancelKeepalive(token);
        try std.testing.expect((try client.keepaliveStatus(token)).outcome == .Cancelled);
        try client.clearKeepalive(token);
        try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
        try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestRemoteForward("localhost", 22));
        if (consumed < packet_len) try consumeKeepaliveTestPacket(&client);
        try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
        try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS)});
        const newer = try client.requestKeepalive();
        try std.testing.expect(newer.id > token.id);
        try consumeKeepaliveTestPacket(&client);
        try std.testing.expect((try client.keepaliveStatus(newer)).outcome == .Pending);
        try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE)});
        try std.testing.expectEqual(Sshz.KeepaliveReply.Failure, (try client.keepaliveStatus(newer)).outcome.Acknowledged);
    }
}

test "cancelled keepalive result cannot be overwritten by its late reply" {
    var prng = std.Random.DefaultPrng.init(53);
    var client = try keepaliveTestClient(prng.random());
    defer client.deinit();
    const token = try client.requestKeepalive();
    try consumeKeepaliveTestPacket(&client);
    try client.cancelKeepalive(token);
    try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE)});
    try std.testing.expect((try client.keepaliveStatus(token)).outcome == .Cancelled);
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
    try client.clearKeepalive(token);
    _ = try client.requestKeepalive();
}

test "global-request completion preserves partially received packets" {
    for ([_]bool{ false, true }) |keepalive| {
        var prng = std.Random.DefaultPrng.init(54);
        var client = try keepaliveTestClient(prng.random());
        defer client.deinit();
        var packet: [64]u8 = undefined;
        const len = buildUnencryptedPacket(&packet, &.{ @intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE), 0, 0, 0, 1, 'x' });
        try feedKeepaliveTestBytes(&client, packet[0 .. Protocol.sizeof_PktHdr + 1]);
        const token = if (keepalive)
            try client.requestKeepalive()
        else blk: {
            try client.requestRemoteForward("localhost", 22);
            break :blk null;
        };
        try consumeKeepaliveTestPacket(&client);
        try feedKeepaliveTestBytes(&client, packet[Protocol.sizeof_PktHdr + 1 .. len]);
        try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE)});
        if (token) |id| {
            try std.testing.expectEqual(Sshz.KeepaliveReply.Failure, (try client.keepaliveStatus(id)).outcome.Acknowledged);
        } else {
            const event = (try client.getNextEvent()).Event;
            try std.testing.expectEqual(@as(u32, 22), event.TcpipForwardFailure.bind_port);
            try client.clearEvent(event);
        }
    }
}

test "keepalive handoff dispatches queued EOF and CLOSE without a reply" {
    for ([_]bool{ false, true }) |partial_body| {
        for ([_]ChannelControl{ .Eof, .Close }) |control| {
            for ([_]bool{ false, true }) |cancelled| {
                var prng = std.Random.DefaultPrng.init(56);
                var client = try keepaliveTestClient(prng.random());
                defer client.deinit();
                const channel = client.session.channel_table.allocChannel(42, 1000, 1000).?;
                channel.state = .DataRx;
                var packet: [64]u8 = undefined;
                const len = buildUnencryptedPacket(&packet, &.{ @intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE), 0, 0, 0, 1, 'x' });
                if (partial_body) {
                    try feedKeepaliveTestBytes(&client, packet[0 .. Protocol.sizeof_PktHdr + 1]);
                } else {
                    _ = try client.getNextEvent();
                }

                const token = try client.requestKeepalive();
                const keepalive_len = (try client.peek(Protocol.MaxSSHPacket)).len;
                try client.consumed(1);
                switch (control) {
                    .Eof => try client.sendChannelEof(channel.local_id),
                    .Close => try client.sendChannelClose(channel.local_id),
                }
                if (cancelled) try client.cancelKeepalive(token);
                const before = (try client.getNextEvent()).ReadyToConsumeAndProduce;
                try std.testing.expectEqual(keepalive_len - 1, before.produce);
                try consumeKeepaliveTestPacket(&client);

                // No peer bytes are delivered between queuing control and
                // this handoff. The public pump must expose the next packet.
                const after = try client.getNextEvent();
                try std.testing.expect(after == .ReadyToConsumeAndProduce);
                try std.testing.expectEqual(before.consume, after.ReadyToConsumeAndProduce.consume);
                var rdr = BufferReader.init(unencryptedPayload(try client.peek(Protocol.MaxSSHPacket)));
                try std.testing.expectEqual(@intFromEnum(switch (control) {
                    .Eof => Protocol.MsgId.SSH_MSG_CHANNEL_EOF,
                    .Close => Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE,
                }), try rdr.readU8());
                try std.testing.expectEqual(@as(u32, 42), try rdr.readU32());
                try std.testing.expectEqual(rdr.payload.len, rdr.off);
                const status = try client.keepaliveStatus(token);
                try std.testing.expectEqual(Sshz.KeepaliveTransmission.HandedToTransport, status.transmission);
                try std.testing.expect(if (cancelled) status.outcome == .Cancelled else status.outcome == .Pending);
                if (control == .Eof) try std.testing.expect(!try client.channelEofFlushed(channel.local_id));
                try client.consumed(1);
                try consumeKeepaliveTestPacket(&client);
                if (control == .Eof) try std.testing.expect(try client.channelEofFlushed(channel.local_id));
                if (partial_body) try feedKeepaliveTestBytes(&client, packet[Protocol.sizeof_PktHdr + 1 .. len]);
                try std.testing.expect((try client.getNextEvent()) == .ReadyToConsume);
            }
        }
    }
}

test "keepalive handoff processes a received disconnect before deferred channel control" {
    var prng = std.Random.DefaultPrng.init(57);
    var client = try keepaliveTestClient(prng.random());
    defer client.deinit();
    const channel = client.session.channel_table.allocChannel(42, 1000, 1000).?;
    channel.state = .DataRx;
    _ = try client.getNextEvent();
    const token = try client.requestKeepalive();
    try client.consumed(1);
    try client.sendChannelEof(channel.local_id);

    var payload: [64]u8 = undefined;
    var writer = BufferWriter.init(&payload, 0);
    try writer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT));
    try writer.writeU32(11);
    try writer.writeU32LenString("closed");
    try writer.writeU32LenString("");
    try feedKeepaliveTestPayload(&client, writer.active());
    try consumeKeepaliveTestPacket(&client);
    const event = (try client.getNextEvent()).Event;
    try std.testing.expectEqualStrings("closed", event.EndSession.ServerDisconnect.description);
    try std.testing.expect((try client.keepaliveStatus(token)).outcome == .Disconnected);
    try std.testing.expectError(IoError.notProducing, client.peek(1));
}

test "keepalive handoff retains rekey guards on deferred channel control" {
    for ([_]bool{ false, true }) |in_progress| {
        var prng = std.Random.DefaultPrng.init(58);
        var client = try keepaliveTestClient(prng.random());
        defer client.deinit();
        const channel = client.session.channel_table.allocChannel(42, 1000, 1000).?;
        channel.state = .DataRx;
        _ = try client.getNextEvent();
        const token = try client.requestKeepalive();
        try client.consumed(1);
        try client.sendChannelEof(channel.local_id);
        if (in_progress) {
            client.session.is_rekeying = true;
            client.session.setSessionState(.KexInitRead);
        } else {
            client.local_rekey_pending = true;
        }
        try consumeKeepaliveTestPacket(&client);
        try std.testing.expectEqual(Sshz.KeepaliveTransmission.HandedToTransport, (try client.keepaliveStatus(token)).transmission);
        try std.testing.expect((try client.getNextEvent()) == .ReadyToConsume);
        try std.testing.expect(channel.eof_pending);
        try std.testing.expect(!channel.eof_sent);
    }
}

test "keepalive deinit terminates queued emitting and handed-off tokens" {
    for ([_]Sshz.KeepaliveTransmission{ .Queued, .Emitting, .HandedToTransport }) |transmission| {
        var prng = std.Random.DefaultPrng.init(55);
        var client = try keepaliveTestClient(prng.random());
        if (transmission == .Queued) {
            client.session.is_rekeying = true;
            client.session.setSessionState(.KexInitRead);
        }
        const token = try client.requestKeepalive();
        if (transmission == .HandedToTransport) try consumeKeepaliveTestPacket(&client);
        const before = try client.keepaliveStatus(token);
        try std.testing.expectEqual(transmission, before.transmission);
        client.deinit();
        try std.testing.expect(client.session.pending_global_request == null);
        try std.testing.expect(client.session.keepalive.?.outcome == .Disconnected);
        try std.testing.expect(before.outcome == .Pending);
        try std.testing.expectError(IoError.SessionTerminated, client.requestKeepalive());
    }
}

test "cancelled queued keepalive is retractable and cancellation is idempotent" {
    var prng = std.Random.DefaultPrng.init(47);
    var client = try keepaliveTestClient(prng.random());
    defer client.deinit();
    client.session.is_rekeying = true;
    client.session.setSessionState(.KexInitRead);
    const token = try client.requestKeepalive();
    try std.testing.expectEqual(Sshz.KeepaliveTransmission.Queued, (try client.keepaliveStatus(token)).transmission);
    try client.cancelKeepalive(token);
    try client.cancelKeepalive(token);
    try client.clearKeepalive(token);
    const newer = try client.requestKeepalive();
    try std.testing.expect(newer.id > token.id);
    try std.testing.expectEqual(@as(u32, 0), client.session.keydata.c2s.seq);
}

test "keepalive grace observes a late reply without installing a timeout policy" {
    var prng = std.Random.DefaultPrng.init(48);
    var client = try keepaliveTestClient(prng.random());
    defer client.deinit();
    try client.initializeDeadlines(0);
    const token = try client.requestKeepalive();
    try consumeKeepaliveTestPacket(&client);
    try client.markKeepaliveFlushed(token);
    try std.testing.expect((try client.tick(1_000_000)) == null);
    try std.testing.expect((try client.keepaliveStatus(token)).outcome == .Pending);
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
    try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE)});
    try std.testing.expectEqual(Sshz.KeepaliveReply.Failure, (try client.keepaliveStatus(token)).outcome.Acknowledged);
}

test "keepalive replies during rekey preserve the key exchange state" {
    var prng = std.Random.DefaultPrng.init(49);
    var client = try keepaliveTestClient(prng.random());
    defer client.deinit();
    const token = try client.requestKeepalive();
    try consumeKeepaliveTestPacket(&client);
    client.session.is_rekeying = true;
    client.session.rekey_resume_state = .ChannelActive;
    client.session.setSessionState(.KexInitRead);
    try feedKeepaliveTestPayload(&client, &.{@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE)});
    try std.testing.expectEqual(Sshz.KeepaliveReply.Failure, (try client.keepaliveStatus(token)).outcome.Acknowledged);
    try std.testing.expectEqual(SessionState.KexInitRead, client.session.sessionState);
    try std.testing.expect(client.session.is_rekeying);
}

test "keepalive rejects unsolicited replies and replies to unframed requests" {
    for ([_]bool{ false, true }) |queued| {
        for ([_]Protocol.MsgId{ .SSH_MSG_REQUEST_SUCCESS, .SSH_MSG_REQUEST_FAILURE }) |reply| {
            var prng = std.Random.DefaultPrng.init(50);
            var client = try keepaliveTestClient(prng.random());
            defer client.deinit();
            var token: ?Sshz.KeepaliveToken = null;
            if (queued) {
                client.session.is_rekeying = true;
                client.session.setSessionState(.KexInitRead);
                token = try client.requestKeepalive();
            }
            try std.testing.expectError(IoError.UnexpectedResponse, feedKeepaliveTestPayload(&client, &.{@intFromEnum(reply)}));
            try std.testing.expectError(IoError.SessionTerminated, client.getNextEvent());
            if (token) |id| try std.testing.expect((try client.keepaliveStatus(id)).outcome == .Disconnected);
        }
    }
}

test "keepalive disconnect and deadline teardown terminate pending observation" {
    for ([_]bool{ false, true }) |deadline| {
        var prng = std.Random.DefaultPrng.init(51);
        var client = try keepaliveTestClient(prng.random());
        defer client.deinit();
        const token = try client.requestKeepalive();
        try consumeKeepaliveTestPacket(&client);
        if (deadline) {
            client.limits.deadlines.idle = 1;
            try client.initializeDeadlines(0);
            try std.testing.expectEqual(Sshz.TimeoutOutcome.Idle, (try client.tick(1)).?);
        } else {
            var payload: [64]u8 = undefined;
            var writer = BufferWriter.init(&payload, 0);
            try writer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT));
            try writer.writeU32(11);
            try writer.writeU32LenString("closed");
            try writer.writeU32LenString("");
            try feedKeepaliveTestPayload(&client, writer.active());
            const event = (try client.getNextEvent()).Event;
            try std.testing.expectEqualStrings("closed", event.EndSession.ServerDisconnect.description);
        }
        const status = try client.keepaliveStatus(token);
        try std.testing.expect(status.outcome == .Disconnected);
        try std.testing.expectError(IoError.SessionTerminated, client.requestKeepalive());
        try std.testing.expectError(IoError.SessionTerminated, client.markKeepaliveFlushed(token));
        try client.clearKeepalive(token);
        client.deinit();
        try std.testing.expect(status.outcome == .Disconnected);
    }
}

test "keepalive tokens never wrap and pre-authentication is not ready" {
    var prng = std.Random.DefaultPrng.init(52);
    var client = try SshzClient.init(prng.random(), "test", std.testing.allocator);
    defer client.deinit();
    try std.testing.expectError(IoError.NotReady, client.requestKeepalive());
    client.session.user_authenticated = true;
    client.session.last_keepalive_id = std.math.maxInt(u64);
    try std.testing.expectError(IoError.ResourceLimitExceeded, client.requestKeepalive());
    try std.testing.expect(client.session.pending_global_request == null);
    try std.testing.expect(client.session.keepalive == null);
}

test "handlePacket: request success maps allocated tcpip-forward port" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    try m.requestRemoteForward("127.0.0.1", 0);
    try m.consumed(m.wr_nbytes);

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS));
    try pw.writeU32(2222);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .TcpipForwardSuccess => |forward| {
                try std.testing.expectEqualStrings("127.0.0.1", forward.bind_address);
                try std.testing.expectEqual(@as(u32, 0), forward.requested_port);
                try std.testing.expectEqual(@as(u32, 2222), forward.bound_port);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: request failure maps cancel-tcpip-forward failure" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    try m.cancelRemoteForward("127.0.0.1", 2200);
    try m.consumed(m.wr_nbytes);

    var payload_backing: [8]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE));

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .CancelTcpipForwardFailure => |cancel| {
                try std.testing.expectEqualStrings("127.0.0.1", cancel.bind_address);
                try std.testing.expectEqual(@as(u32, 2200), cancel.bind_port);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "openSessionChannel rejects another open while one is pending" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);

    _ = try m.openSessionChannel();
    try std.testing.expectError(IoError.cannotAcceptWrite, m.openSessionChannel());
}

test "openSessionChannel can open another raw channel after confirmation" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);

    const first_id = try m.openSessionChannel();
    try m.consumed(m.wr_nbytes);

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(first_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.iostate_rd = .Idle;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try m.clearEvent(.{ .ChannelOpened = first_id });

    const second_id = try m.openSessionChannel();
    try std.testing.expectEqual(@as(u32, 1), second_id);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try rdr.readU8());
    try std.testing.expectEqualStrings("session", try rdr.readU32LenString());
    try std.testing.expectEqual(second_id, try rdr.readU32());
}

test "unconfirmed client channel defers close until remote id is known" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const existing = m.session.channel_table.allocChannel(0, 1000, 1000).?;
    existing.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    const channel_id = try m.openSessionChannel();
    const pending = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expect(!pending.remote_id_known);

    try m.sendChannelClose(channel_id);
    try std.testing.expect(pending.close_pending);
    try std.testing.expect(pending.control_in_flight == null);

    const open_packet = try m.peek(Protocol.MaxSSHPacket);
    var open_reader = BufferReader.init(unencryptedPayload(open_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try open_reader.readU8());
    try m.consumed(open_packet.len);
    try std.testing.expect(!pending.remote_id_known);
    try std.testing.expect(pending.control_in_flight == null);

    var confirmation_payload_buf: [32]u8 = undefined;
    var confirmation = BufferWriter.init(&confirmation_payload_buf, 0);
    try confirmation.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try confirmation.writeU32(channel_id);
    try confirmation.writeU32(77);
    try confirmation.writeU32(1000);
    try confirmation.writeU32(1000);
    const confirmation_len = buildUnencryptedPacket(&m.iobuf_rd, confirmation.active());
    m.iostate_rd = .Idle;
    try m.session.handlePacket(m.iobuf_rd[0..confirmation_len], &m);
    const opened = try m.getNextEvent();
    switch (opened) {
        .Event => |event| switch (event) {
            .ChannelOpened => |opened_id| try std.testing.expectEqual(channel_id, opened_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try m.clearEvent(.{ .ChannelOpened = channel_id });

    const close_packet = try m.peek(Protocol.MaxSSHPacket);
    var close_reader = BufferReader.init(unencryptedPayload(close_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE), try close_reader.readU8());
    try std.testing.expectEqual(@as(u32, 77), try close_reader.readU32());
    try std.testing.expect(pending.remote_id_known);
}

test "unconfirmed client channel reports queued EOF as not flushed" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const existing = m.session.channel_table.allocChannel(0, 1000, 1000).?;
    existing.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    const channel_id = try m.openSessionChannel();
    const pending = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expect(!pending.remote_id_known);

    try m.sendChannelEof(channel_id);
    try std.testing.expect(pending.eof_pending);
    try std.testing.expect(!(try m.channelEofFlushed(channel_id)));
}

test "handlePacket: SSH_MSG_DEBUG with always_display=true" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DEBUG));
    try pw.writeBoolean(true);
    try pw.writeU32LenString("test debug message");
    try pw.writeU32LenString("en");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setIoSessionState(.ReadPktHdr);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
}

test "handlePacket: SSH_MSG_DEBUG with always_display=false" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DEBUG));
    try pw.writeBoolean(false);
    try pw.writeU32LenString("quiet debug");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setIoSessionState(.ReadPktHdr);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
}

test "handlePacket: SSH_MSG_DISCONNECT surfaces reason code" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT));
    try pw.writeU32(11); // SSH_DISCONNECT_BY_APPLICATION
    try pw.writeU32LenString("shutting down");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .EndSession => |reason| switch (reason) {
                .ServerDisconnect => |r| {
                    try std.testing.expectEqual(@as(u32, 11), r.code);
                    try std.testing.expectEqualStrings("shutting down", r.description);
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: auth-agent channel open requires opt-in" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString(Protocol.channel_type_auth_agent_openssh);
    try pw.writeU32(42);
    try pw.writeU32(32768);
    try pw.writeU32(32768);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expectEqual(@as(u32, 0), m.session.channel_table.activeCount());
    try std.testing.expect(m.iostate_wr != .Idle);
}

test "handlePacket: connection protocol messages are rejected before authentication" {
    // Regression: an unauthenticated peer must not be able to open an
    // auth-agent channel before key exchange and userauth complete, which
    // would otherwise hand it a pipe to the local SSH agent.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.session.enableAgentForwarding();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString(Protocol.channel_type_auth_agent);
    try pw.writeU32(42);
    try pw.writeU32(32768);
    try pw.writeU32(32768);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    // sessionState is still .Init: no kex, no host key check, no userauth.
    try std.testing.expectError(
        error.UnexpectedResponse,
        m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m),
    );
    try std.testing.expectEqual(@as(u32, 0), m.session.channel_table.activeCount());
}

test "handlePacket: peer rekey is rejected before the initial key exchange completes" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();
    try m.session.setPeerProtocolVersion("SSH-2.0-test_server");

    var server_payload_buf: [512]u8 = undefined;
    var server_payload = BufferWriter.init(&server_payload_buf, 0);
    try writeKexInitPayload(&server_payload);
    const server_packet_len = buildUnencryptedPacket(&m.iobuf_rd, server_payload.active());
    // .ChannelActive without a completed first exchange must not be treated as a rekey.
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);

    try std.testing.expectError(
        error.UnexpectedResponse,
        m.session.handlePacket(m.iobuf_rd[0..server_packet_len], &m),
    );
    try std.testing.expect(!m.session.is_rekeying);
}

test "handlePacket: auth-agent channel open creates agent channel when enabled" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.session.enableAgentForwarding();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString(Protocol.channel_type_auth_agent);
    try pw.writeU32(42);
    try pw.writeU32(32768);
    try pw.writeU32(32768);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const chan = m.session.channel_table.findByLocalId(0).?;
    try std.testing.expectEqual(.AgentForward, chan.kind);
    try std.testing.expectEqual(@as(u32, 42), chan.remote_id);
    try std.testing.expectEqual(ChannelState.ConfirmWrite, chan.state);
    try std.testing.expectEqual(SessionState.ChannelActive, m.session.sessionState);
}

test "handlePacket: userauth replies are rejected outside the authentication phase" {
    // Regression: a malicious server could send KEXINIT mid-userauth and then
    // USERAUTH_SUCCESS. The success handler would overwrite the parked
    // .KexInitRead with .ChannelOpenReq, so KEX_ECDH_INIT was never sent and
    // is_rekeying stayed latched forever, wedging the session.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.current_auth_method = .Password;
    m.session.session_id_established = true;
    m.session.rekey_resume_state = .AuthMethodQueued;
    m.session.is_rekeying = true;
    m.session.setSessionState(.KexInitRead);

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS));

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    try std.testing.expectError(
        error.UnexpectedResponse,
        m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m),
    );
    try std.testing.expect(!m.session.user_authenticated);
    try std.testing.expectEqual(SessionState.KexInitRead, m.session.sessionState);
}

test "handlePacket: channel data is accepted while a rekey is in flight" {
    // Regression: RFC 4253 s9 allows connection-protocol packets that the peer
    // sent before it saw our KEXINIT to arrive during a rekey. Gating on
    // sessionState would drop them; the authentication latch must not.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(42, 32768, Protocol.MaxChannelDataLen).?;
    chan.state = .DataRx;
    m.session.user_authenticated = true;

    // Mid-rekey: we sent our KEXINIT and are parked waiting for the peer's,
    // so sessionState has legitimately left the connection-protocol set.
    m.session.session_id_established = true;
    m.session.rekey_resume_state = .ChannelActive;
    m.session.is_rekeying = true;
    m.session.setSessionState(.KexInitRead);

    var payload_backing: [64]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(chan.local_id);
    try payload.writeU32LenString("hello");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .RxData => |channel_data| {
                try std.testing.expectEqual(chan.local_id, channel_data.channel);
                try std.testing.expectEqualSlices(u8, "hello", channel_data.data);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    // The in-flight packet must not clobber the parked key-exchange state,
    // or the peer's KEXINIT would later be misread as peer-initiated.
    try std.testing.expectEqual(SessionState.KexInitRead, m.session.sessionState);
    try std.testing.expectEqual(SessionState.ChannelActive, m.session.rekey_resume_state.?);
}

test "a client with two channels can tell their data apart" {
    // Reaching Connected opens a session channel and asks for a pty and a
    // shell, so any client that then opens a `direct-tcpip` tunnel has two
    // channels delivering data. Without the channel on the event the two
    // byte streams are indistinguishable, and splicing shell output into a
    // tunnel corrupts whatever protocol is running over it -- silently, and
    // far from here.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.user_authenticated = true;
    const shell = m.session.channel_table.allocChannel(1, 32768, Protocol.MaxChannelDataLen).?;
    shell.state = .DataRx;
    const tunnel = m.session.channel_table.allocChannel(2, 32768, Protocol.MaxChannelDataLen).?;
    tunnel.state = .DataRx;
    try std.testing.expect(shell.local_id != tunnel.local_id);

    // What bash actually sends first: ESC [ ? 2 0 0 4 h, bracketed paste on.
    // Read as TLS it is a record header claiming 0x3f32 bytes that will
    // never arrive.
    try expectChannelData(&m, shell.local_id, "\x1b[?2004h");
    try expectChannelData(&m, tunnel.local_id, "\x17\x03\x03\x00\xa2");
}

/// Feeds one `SSH_MSG_CHANNEL_DATA` and asserts the event names its channel.
fn expectChannelData(m: *SshzClient, channel: u32, data: []const u8) !void {
    var payload_backing: [64]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(channel);
    try payload.writeU32LenString(data);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
    m.iostate_rd = .Idle;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], m);

    switch (try m.getNextEvent()) {
        .Event => |code| switch (code) {
            .RxData => |received| {
                try std.testing.expectEqual(channel, received.channel);
                try std.testing.expectEqualSlices(u8, data, received.data);
                try m.clearEvent(.{ .RxData = received });
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

fn writeClientChannelPacket(m: *SshzClient, channel: u32, data: []const u8) !void {
    var payload_backing: [64]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(channel);
    try payload.writeU32LenString(data);

    var packet: [96]u8 = undefined;
    const packet_len = buildUnencryptedPacket(&packet, payload.active());
    try m.write(packet[0..Protocol.sizeof_PktHdr]);
    try m.write(packet[Protocol.sizeof_PktHdr..packet_len]);
}

fn expectAndClearClientData(m: *SshzClient, channel: u32, data: []const u8) !void {
    switch (try m.getNextEvent()) {
        .Event => |code| switch (code) {
            .RxData => |received| {
                try std.testing.expectEqual(channel, received.channel);
                try std.testing.expectEqualSlices(u8, data, received.data);
                try m.clearEvent(.{ .RxData = received });
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "client window adjustment completion preserves concurrently received packet" {
    const limits = Sshz.ResourceLimits{
        .initial_channel_window = 12,
        .max_channel_window = 12,
        .channel_packet_size = 4,
        .max_peer_packet_size = 4,
    };
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.initWithLimits(prng.random(), "testuser", std.testing.allocator, limits);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(42, 12, 4).?;
    chan.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, Protocol.sizeof_PktHdr, .{ .ReadPktBody = m.iobuf_rd[0..Protocol.sizeof_PktHdr] });

    try writeClientChannelPacket(&m, chan.local_id, "aaaa");
    try expectAndClearClientData(&m, chan.local_id, "aaaa");
    try writeClientChannelPacket(&m, chan.local_id, "bbbb");
    try expectAndClearClientData(&m, chan.local_id, "bbbb");

    const first_adjust_len = m.wr_nbytes;
    try std.testing.expect(first_adjust_len > 1);
    var first_adjust = BufferReader.init(unencryptedPayload(try m.peek(first_adjust_len)));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST), try first_adjust.readU8());
    try std.testing.expectEqual(chan.remote_id, try first_adjust.readU32());
    try std.testing.expectEqual(@as(u32, 8), try first_adjust.readU32());
    try m.consumed(1);
    try writeClientChannelPacket(&m, chan.local_id, "cccc");
    try std.testing.expect(m.session.ioSessionState == .ReadPktCompletion);
    try m.consumed(first_adjust_len - 1);
    try expectAndClearClientData(&m, chan.local_id, "cccc");

    try writeClientChannelPacket(&m, chan.local_id, "dddd");
    try expectAndClearClientData(&m, chan.local_id, "dddd");
    const second_adjust_len = m.wr_nbytes;
    try std.testing.expect(second_adjust_len > 1);
    var second_adjust = BufferReader.init(unencryptedPayload(try m.peek(second_adjust_len)));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST), try second_adjust.readU8());
    try std.testing.expectEqual(chan.remote_id, try second_adjust.readU32());
    try std.testing.expectEqual(@as(u32, 8), try second_adjust.readU32());
    try m.consumed(1);
    try writeClientChannelPacket(&m, chan.local_id, "eeee");
    try std.testing.expect(m.session.ioSessionState == .ReadPktCompletion);
    try m.consumed(second_adjust_len - 1);
    try expectAndClearClientData(&m, chan.local_id, "eeee");
    try std.testing.expectEqual(@as(u32, 8), chan.local_window);
}

test "client defers receive window adjustment across rekey" {
    const limits = Sshz.ResourceLimits{
        .initial_channel_window = 12,
        .max_channel_window = 12,
        .channel_packet_size = 4,
        .max_peer_packet_size = 4,
    };
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.initWithLimits(prng.random(), "testuser", std.testing.allocator, limits);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(42, 12, 4).?;
    chan.state = .DataRx;
    chan.local_window = 4;
    m.session.user_authenticated = true;
    m.session.is_rekeying = true;
    m.session.rekey_resume_state = .ChannelActive;
    m.session.setSessionState(.KexInitRead);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, Protocol.sizeof_PktHdr, .{ .ReadPktBody = m.iobuf_rd[0..Protocol.sizeof_PktHdr] });

    try m.advance();
    try std.testing.expectEqual(@as(usize, 0), m.wr_nbytes);
    try std.testing.expectEqual(@as(u32, 4), chan.local_window);

    m.iostate_rd = .Idle;
    m.session.is_rekeying = false;
    m.session.rekey_resume_state = null;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.Idle);
    try m.advance();
    try std.testing.expect(m.wr_nbytes > 0);
    try std.testing.expectEqual(@as(u32, 12), chan.local_window);
}

test "handlePacket: agent channel data surfaces AgentData event" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.AgentForward, 42, 32768, 32768).?;
    chan.state = .DataRx;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try pw.writeU32(chan.local_id);
    try pw.writeU32LenString("agent-bytes");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .AgentData => |data| {
                try std.testing.expectEqual(chan.local_id, data.channel);
                try std.testing.expectEqualStrings("agent-bytes", data.data);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "client receives exactly advertised maximum channel data" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(42, 32768, Protocol.MaxChannelDataLen).?;
    chan.state = .DataRx;
    m.session.user_authenticated = true;

    var channel_data: [Protocol.MaxChannelDataLen]u8 = undefined;
    for (&channel_data, 0..) |*byte, index| byte.* = @truncate(index);
    var payload_backing: [Protocol.MaxPayload]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(chan.local_id);
    try payload.writeU32LenString(&channel_data);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .RxData => |received| {
                try std.testing.expectEqual(chan.local_id, received.channel);
                try std.testing.expectEqual(@as(usize, Protocol.MaxChannelDataLen), received.data.len);
                try std.testing.expectEqualSlices(u8, &channel_data, received.data);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    // The window is consumed by exactly what arrived. Asserting it reaches
    // zero would only be true when the whole window is one packet, which was
    // the old default and is the reason large transfers stalled.
    try std.testing.expectEqual(
        Sshz.default_channel_window - Protocol.MaxChannelDataLen,
        chan.local_window,
    );
}

test "client runtime channel buffer pending and peer limits enforce boundaries" {
    const limits = Sshz.ResourceLimits{
        .initial_channel_window = 100,
        .max_channel_window = 100,
        .channel_packet_size = 50,
        .max_peer_packet_size = 50,
        .max_channel_buffered_data = 8,
        .max_pending_buffered_data = 12,
    };
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.initWithLimits(prng.random(), "testuser", std.testing.allocator, limits);
    defer session.deinit();

    try session.validatePeerChannel(99, 49);
    try session.validatePeerChannel(100, 50);
    try std.testing.expectError(IoError.InvalidChannelParameters, session.validatePeerChannel(101, 50));
    try std.testing.expectError(IoError.InvalidChannelParameters, session.validatePeerChannel(100, 51));

    const first = session.channel_table.allocChannel(1, 100, 50).?;
    const second = session.channel_table.allocChannel(2, 100, 50).?;
    try std.testing.expectEqual(@as(usize, 8), (try session.getChannelWriteBuffer(first.local_id)).len);
    try std.testing.expectError(IoError.tooBig, session.channelWriteComplete(first.local_id, 9));
    try session.channelWriteComplete(first.local_id, 8);
    try std.testing.expectError(IoError.ResourceLimitExceeded, session.channelWriteComplete(second.local_id, 5));
    try session.channelWriteComplete(second.local_id, 4);
    try std.testing.expectEqual(@as(usize, 12), session.pendingBufferedData());
}

test "client rejects channel data above packet and receive window limits" {
    const limits = Sshz.ResourceLimits{
        .initial_channel_window = 8,
        .max_channel_window = 8,
        .channel_packet_size = 4,
        .max_peer_packet_size = 4,
        .max_channel_buffered_data = 4,
        .max_pending_buffered_data = 4,
    };
    var prng = std.Random.DefaultPrng.init(42);

    var packet_client = try SshzClient.initWithLimits(prng.random(), "testuser", std.testing.allocator, limits);
    defer packet_client.deinit();
    const packet_chan = packet_client.session.channel_table.allocChannel(42, 8, 4).?;
    packet_chan.state = .DataRx;
    packet_client.session.user_authenticated = true;
    var payload_backing: [64]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(packet_chan.local_id);
    try payload.writeU32LenString("12345");
    const packet_len = buildUnencryptedPacket(&packet_client.iobuf_rd, payload.active());
    try std.testing.expectError(
        error.ChannelPacketTooLarge,
        packet_client.session.handlePacket(packet_client.iobuf_rd[0..packet_len], &packet_client),
    );
    try std.testing.expectEqual(@as(u32, 8), packet_chan.local_window);

    var window_client = try SshzClient.initWithLimits(prng.random(), "testuser", std.testing.allocator, limits);
    defer window_client.deinit();
    const window_chan = window_client.session.channel_table.allocChannel(42, 8, 4).?;
    window_chan.state = .DataRx;
    window_client.session.user_authenticated = true;
    window_chan.local_window = 3;
    payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(window_chan.local_id);
    try payload.writeU32LenString("1234");
    const window_len = buildUnencryptedPacket(&window_client.iobuf_rd, payload.active());
    try std.testing.expectError(
        error.ReceiveWindowExceeded,
        window_client.session.handlePacket(window_client.iobuf_rd[0..window_len], &window_client),
    );
    try std.testing.expectEqual(@as(u32, 3), window_chan.local_window);
}

test "handlePacket: SSH_MSG_CHANNEL_CLOSE when not yet sent triggers close reply" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.close_sent = false;

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE));
    try pw.writeU32(0);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(SessionState.ChannelActive, m.session.sessionState);
    try std.testing.expectEqual(ChannelState.DataRx, chan.state);
    try std.testing.expect(chan.close_pending);
    try std.testing.expectEqual(@as(usize, 0), chan.write_buf_nbytes);
}

test "ordinary channel EOF is emitted once and does not affect peers" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const eof_channel = m.session.channel_table.allocChannel(10, 32768, 32768).?;
    eof_channel.state = .DataRx;
    const peer_channel = m.session.channel_table.allocChannel(11, 32768, 32768).?;
    peer_channel.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_EOF, eof_channel.local_id);
    try expectChannelEofForTest(&m, eof_channel.local_id);
    try m.clearEvent(.{ .ChannelEof = eof_channel.local_id });

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_EOF, eof_channel.local_id);
    switch (try m.getNextEvent()) {
        .Event => return error.TestUnexpectedResult,
        else => {},
    }
    try std.testing.expect(!peer_channel.eof_received);
    try expectChannelData(&m, peer_channel.local_id, "peer-still-active");
}

test "handlePacket: SSH_MSG_CHANNEL_CLOSE emits close before terminal end" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel and mark close as sent
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.close_sent = true;

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE));
    try pw.writeU32(0);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelClosed => |channel_id| try std.testing.expectEqual(@as(u32, 0), channel_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(m.session.channel_table.findByLocalId(0) != null);
    try m.clearEvent(.{ .ChannelClosed = 0 });
    switch (try m.getNextEvent()) {
        .Event => |code| switch (code) {
            .EndSession => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: SSH_MSG_USERAUTH_BANNER surfaces banner event" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_BANNER));
    try pw.writeU32LenString("Welcome to the server!\r\n");
    try pw.writeU32LenString("en");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .Banner => |text| {
                try std.testing.expectEqualStrings("Welcome to the server!\r\n", text);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "clearing a borrowed plaintext event releases packet storage" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_BANNER));
    try payload.writeU32LenString("borrowed-sensitive-banner");
    try payload.writeU32LenString("en");
    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const event = try m.getNextEvent();
    const code = switch (event) {
        .Event => |code| code,
        else => return error.TestUnexpectedResult,
    };
    switch (code) {
        .Banner => |banner| try std.testing.expectEqualStrings("borrowed-sensitive-banner", banner),
        else => return error.TestUnexpectedResult,
    }
    try m.clearEvent(code);
    for (m.iobuf_rd) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (m.iobuf_decompressed) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "client session deinit zeros sensitive fields" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);

    try session.setPrivateKey("fake-key-data-for-testing");
    try session.setPrivateKeyPassphrase("my-secret-passphrase");
    try session.setAuthPassphrase("my-auth-password");
    @memset(&session.shared_secret_k, 0xAA);
    @memset(&session.session_id, 0xBB);
    @memset(std.mem.asBytes(&session.ecdh_ephem_keypair), 0xCC);
    session.ecdh_ephem_keypair_active = true;

    session.deinit();

    try std.testing.expect(session.privkey_ascii == null);
    try std.testing.expect(session.privkey_passphrase == null);
    try std.testing.expect(session.auth_passphrase == null);
    for (session.shared_secret_k) |b| try std.testing.expectEqual(@as(u8, 0), b);
    for (session.session_id) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expect(session.private_key == null);
    try std.testing.expect(!session.ecdh_ephem_keypair_active);
    try std.testing.expect(!session.kex_hasher.active);
    for (std.mem.asBytes(&session.ecdh_ephem_keypair)) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "setPrivateKey replaces previous key" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    try session.setPrivateKey("first-key");
    try session.setPrivateKey("second-key");
    try std.testing.expectEqualStrings("second-key", session.privkey_ascii.?);
}

test "client auth inputs are released after packet construction and decode errors" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.setAuthPassphrase("packet-password");
    m.session.encrypted = false;
    m.session.setSessionState(.PasswordAuthReq);
    try m.session.advanceSession(&m);
    try std.testing.expect(m.session.auth_passphrase == null);
    const packet = try m.peek(Protocol.MaxSSHPacket);
    try m.consumed(packet.len);
    for (m.iobuf_wr) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    try m.setPrivateKey("not-an-openssh-key");
    try m.setPrivateKeyPassphrase("wrong-passphrase");
    m.iostate_wr = .Idle;
    m.session.setSessionState(.PubkeyAuthDecodeKeyPassword);
    try std.testing.expectError(PrivKeyError.BadPrivKey, m.session.advanceSession(&m));
    try std.testing.expect(m.session.privkey_ascii == null);
    try std.testing.expect(m.session.privkey_passphrase == null);
    try std.testing.expect(m.session.private_key == null);
}

test "successful public-key authentication packet releases copied and decoded key material" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.setPrivateKey(@import("privkey.zig").testkey_valid);
    m.session.encrypted = false;
    m.session.setSessionState(.PubkeyAuthDecodeKeyPasswordless);
    try m.session.advanceSession(&m);
    try std.testing.expect(m.session.privkey_ascii == null);
    try std.testing.expect(m.session.private_key != null);

    m.session.setSessionState(.PubkeyAuthReq);
    try m.session.advanceSession(&m);
    try std.testing.expect(m.session.private_key == null);
    try std.testing.expect(m.session.privkey_passphrase == null);
}

test "client channel_close_sent starts false" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();
    // No channels allocated yet, so no close_sent to check
    try std.testing.expectEqual(@as(u32, 0), session.channel_table.activeCount());
}

test "client channel write buffer is MaxChannelDataLen" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    // Allocate a channel first
    _ = session.channel_table.allocChannel(0, 0, 0);
    const buf = try session.getChannelWriteBuffer(0);
    try std.testing.expectEqual(Protocol.MaxChannelDataLen, buf.len);
}

test "client direct write retains suffix across peer packet and window limits" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(77, 1500, 1000).?;
    chan.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    const total_len: usize = 2500;
    for (chan.write_buf[0..total_len], 0..) |*byte, index| byte.* = @truncate(index);

    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 1, .ReadPktHdr);
    try m.channelWriteComplete(chan.local_id, total_len);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
    try std.testing.expectEqual(@as(usize, total_len), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(usize, 1000), chan.tx_in_flight_len);
    try std.testing.expectEqual(@as(usize, 0), (try m.getChannelWriteBuffer(chan.local_id)).len);
    try std.testing.expectError(IoError.cannotAcceptWrite, m.channelWriteComplete(chan.local_id, 1));
    try std.testing.expect(!(try m.channelEofFlushed(chan.local_id)));
    try m.sendChannelEof(chan.local_id);
    try std.testing.expect(chan.eof_pending);
    try std.testing.expect(!chan.eof_sent);
    try std.testing.expect(!(try m.channelEofFlushed(chan.local_id)));

    var inbound_payload_buf: [32]u8 = undefined;
    var inbound_payload = BufferWriter.init(&inbound_payload_buf, 0);
    try inbound_payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA));
    try inbound_payload.writeU32(chan.local_id);
    try inbound_payload.writeU32(1);
    try inbound_payload.writeU32LenString("peer-data");
    const inbound_packet_len = buildUnencryptedPacket(&m.iobuf_rd, inbound_payload.active());
    m.iostate_rd = .Idle;
    m.session.setIoSessionState(.{ .ReadPktCompletion = m.iobuf_rd[0..inbound_packet_len] });

    var received: [total_len]u8 = undefined;
    var received_len: usize = 0;
    received_len += try consumeProducedChannelDataForTest(&m, &received, received_len);
    try std.testing.expectEqual(@as(usize, 1000), received_len);
    try std.testing.expectEqual(@as(usize, 1500), chan.write_buf_nbytes);
    try std.testing.expect(!(try m.channelEofFlushed(chan.local_id)));

    const inbound_event = try m.getNextEvent();
    switch (inbound_event) {
        .Event => |event| switch (event) {
            .RxExtendedData => |data| {
                try std.testing.expectEqual(chan.local_id, data.channel);
                try std.testing.expectEqual(@as(u32, 1), data.data_type);
                try std.testing.expectEqualStrings("peer-data", data.data);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try m.clearEvent(.{ .RxExtendedData = .{
        .channel = chan.local_id,
        .data_type = 1,
        .data = "peer-data",
    } });

    received_len += try consumeProducedChannelDataForTest(&m, &received, received_len);
    try std.testing.expectEqual(@as(usize, 1500), received_len);
    try std.testing.expectEqual(@as(usize, 1000), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(u32, 0), chan.peer_window);
    try std.testing.expectEqual(@as(usize, 0), chan.tx_in_flight_len);

    m.iostate_rd = .Idle;
    var adjust_payload_buf: [16]u8 = undefined;
    var adjust_payload = BufferWriter.init(&adjust_payload_buf, 0);
    try adjust_payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
    try adjust_payload.writeU32(chan.local_id);
    try adjust_payload.writeU32(2000);
    const adjust_packet_len = buildUnencryptedPacket(&m.iobuf_rd, adjust_payload.active());
    try m.session.handlePacket(m.iobuf_rd[0..adjust_packet_len], &m);
    try m.advance();
    try m.advance();

    received_len += try consumeProducedChannelDataForTest(&m, &received, received_len);
    try std.testing.expectEqual(total_len, received_len);
    try std.testing.expectEqual(@as(usize, 0), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(u32, 1000), chan.peer_window);
    for (received, 0..) |byte, index| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);

    const eof_packet = try m.peek(Protocol.MaxSSHPacket);
    var eof_reader = BufferReader.init(unencryptedPayload(eof_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF), try eof_reader.readU8());
    try std.testing.expectEqual(chan.remote_id, try eof_reader.readU32());
    try std.testing.expect(chan.eof_sent);
    try std.testing.expect(!chan.eof_pending);
    try std.testing.expect(!(try m.channelEofFlushed(chan.local_id)));
    try m.consumed(eof_packet.len);
    try std.testing.expect(try m.channelEofFlushed(chan.local_id));
    try std.testing.expectError(IoError.UnexpectedResponse, m.channelEofFlushed(9999));
    try std.testing.expectEqual(@as(usize, 0), (try m.getChannelWriteBuffer(chan.local_id)).len);
    try std.testing.expectError(IoError.UnexpectedResponse, m.channelWriteComplete(chan.local_id, 1));
}

test "automatic session ends after session channel closes before agent channel" {
    var prng = std.Random.DefaultPrng.init(46);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const session_chan = m.session.channel_table.allocChannel(20, 32768, 32768).?;
    session_chan.state = .DataRx;
    session_chan.close_sent = true;
    m.session.automatic_session_channel_id = session_chan.local_id;
    const session_id = session_chan.local_id;

    const agent_chan = m.session.channel_table.allocChannelKind(.AgentForward, 21, 32768, 32768).?;
    agent_chan.state = .DataRx;
    agent_chan.close_sent = true;
    const agent_id = agent_chan.local_id;

    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_CLOSE, session_id);
    try expectChannelClosedForTest(&m, session_id);
    try m.clearEvent(.{ .ChannelClosed = session_id });
    try std.testing.expect(m.session.channel_table.findByLocalId(session_id) == null);
    try std.testing.expect(m.session.channel_table.findByLocalId(agent_id) != null);

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_CLOSE, agent_id);
    try expectAgentChannelClosedForTest(&m, agent_id);
    try m.clearEvent(.{ .AgentChannelClosed = agent_id });
    try expectDisconnectForTest(&m);
}

test "automatic session ends after agent channel closes before session channel" {
    var prng = std.Random.DefaultPrng.init(47);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const session_chan = m.session.channel_table.allocChannel(22, 32768, 32768).?;
    session_chan.state = .DataRx;
    session_chan.close_sent = true;
    m.session.automatic_session_channel_id = session_chan.local_id;
    const session_id = session_chan.local_id;

    const agent_chan = m.session.channel_table.allocChannelKind(.AgentForward, 23, 32768, 32768).?;
    agent_chan.state = .DataRx;
    agent_chan.close_sent = true;
    const agent_id = agent_chan.local_id;

    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_CLOSE, agent_id);
    try expectAgentChannelClosedForTest(&m, agent_id);
    try m.clearEvent(.{ .AgentChannelClosed = agent_id });
    try std.testing.expect(m.session.channel_table.findByLocalId(agent_id) == null);
    try std.testing.expect(m.session.channel_table.findByLocalId(session_id) != null);
    switch (try m.getNextEvent()) {
        .Event => return error.TestUnexpectedResult,
        else => {},
    }

    try deliverChannelControlForTest(&m, .SSH_MSG_CHANNEL_CLOSE, session_id);
    try expectChannelClosedForTest(&m, session_id);
    try m.clearEvent(.{ .ChannelClosed = session_id });
    try expectDisconnectForTest(&m);
}

test "peer close pending during fragment discards suffix before close reply" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(77, 2500, 1000).?;
    chan.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    for (chan.write_buf[0..2500], 0..) |*byte, index| byte.* = @truncate(index);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 1, .ReadPktHdr);
    try m.channelWriteComplete(chan.local_id, 2500);

    var close_payload_buf: [8]u8 = undefined;
    var close_payload = BufferWriter.init(&close_payload_buf, 0);
    try close_payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE));
    try close_payload.writeU32(chan.local_id);
    const close_packet_len = buildUnencryptedPacket(&m.iobuf_rd, close_payload.active());
    m.iostate_rd = .Idle;
    m.session.setIoSessionState(.{ .ReadPktCompletion = m.iobuf_rd[0..close_packet_len] });

    var first_fragment: [1000]u8 = undefined;
    _ = try consumeProducedChannelDataForTest(&m, &first_fragment, 0);

    const close_reply = try m.peek(Protocol.MaxSSHPacket);
    var close_reader = BufferReader.init(unencryptedPayload(close_reply));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE), try close_reader.readU8());
    try std.testing.expectEqual(chan.remote_id, try close_reader.readU32());
    try std.testing.expect(chan.close_received);
    try std.testing.expect(chan.close_sent);
    try std.testing.expectEqual(@as(usize, 0), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(usize, 0), chan.tx_in_flight_len);
    const local_id = chan.local_id;
    try m.consumed(close_reply.len);
    try expectChannelClosedForTest(&m, local_id);
    try std.testing.expect(m.session.channel_table.findByLocalId(local_id) != null);
    try m.clearEvent(.{ .ChannelClosed = local_id });
}

test "local close discards window-blocked suffix after in-flight fragment" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(77, 1000, 1000).?;
    chan.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    for (chan.write_buf[0..2000], 0..) |*byte, index| byte.* = @truncate(index);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 1, .ReadPktHdr);
    try m.channelWriteComplete(chan.local_id, 2000);
    try m.sendChannelClose(chan.local_id);
    try std.testing.expect(chan.close_pending);
    try std.testing.expectEqual(@as(u32, 0), chan.peer_window);

    var first_fragment: [1000]u8 = undefined;
    _ = try consumeProducedChannelDataForTest(&m, &first_fragment, 0);

    const close_packet = try m.peek(Protocol.MaxSSHPacket);
    var close_reader = BufferReader.init(unencryptedPayload(close_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE), try close_reader.readU8());
    try std.testing.expectEqual(chan.remote_id, try close_reader.readU32());
    try std.testing.expectEqual(@as(usize, 0), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(usize, 0), chan.tx_in_flight_len);
    try std.testing.expectEqual(ChannelControl.Close, chan.control_in_flight.?);
}

test "client completion schedules pending control on another channel" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const channel_a = m.session.channel_table.allocChannel(10, 1000, 1000).?;
    channel_a.state = .DataRx;
    const channel_b = m.session.channel_table.allocChannel(20, 1000, 1000).?;
    channel_b.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    const data_len: usize = 100;
    for (channel_a.write_buf[0..data_len], 0..) |*byte, index| byte.* = @truncate(index);

    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 1, .ReadPktHdr);
    try m.channelWriteComplete(channel_a.local_id, data_len);
    try m.sendChannelClose(channel_b.local_id);
    try std.testing.expect(channel_b.close_pending);

    var received: [data_len]u8 = undefined;
    _ = try consumeProducedChannelDataForTest(&m, &received, 0);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
    try std.testing.expect(m.iostate_rd != .Idle);

    const close_packet = try m.peek(Protocol.MaxSSHPacket);
    var close_reader = BufferReader.init(unencryptedPayload(close_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE), try close_reader.readU8());
    try std.testing.expectEqual(channel_b.remote_id, try close_reader.readU32());
}

test "client close completion dispatches next channel control during active read" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const first = m.session.channel_table.allocChannel(10, 1000, 1000).?;
    first.state = .DataRx;
    const second = m.session.channel_table.allocChannel(20, 1000, 1000).?;
    second.state = .DataRx;
    m.session.session_id_established = true;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 1, .ReadPktHdr);

    try m.sendChannelClose(first.local_id);
    try m.sendChannelEof(second.local_id);
    try std.testing.expectEqual(ChannelControl.Close, first.control_in_flight.?);
    try std.testing.expect(second.eof_pending);

    const first_close = try m.peek(Protocol.MaxSSHPacket);
    var close_reader = BufferReader.init(unencryptedPayload(first_close));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE), try close_reader.readU8());
    try m.consumed(first_close.len);

    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
    try std.testing.expect(m.iostate_rd != .Idle);
    const second_eof = try m.peek(Protocol.MaxSSHPacket);
    var eof_reader = BufferReader.init(unencryptedPayload(second_eof));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF), try eof_reader.readU8());
    try std.testing.expectEqual(second.remote_id, try eof_reader.readU32());
}

test "channelWriteComplete rejects oversized writes" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    _ = session.channel_table.allocChannel(0, 0, 0);
    const result = session.channelWriteComplete(0, Protocol.MaxChannelDataLen + 1);
    try std.testing.expectError(IoError.tooBig, result);
}

test "channelWriteComplete accepts max-size write" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    const chan = session.channel_table.allocChannel(0, 0, 0).?;
    chan.state = .DataRx;
    session.setIoSessionState(.ReadPktHdr);

    try session.channelWriteComplete(0, Protocol.MaxChannelDataLen);
    try std.testing.expectEqual(@as(usize, Protocol.MaxChannelDataLen), chan.write_buf_nbytes);
}

test "peer_window starts at zero" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();
    // Channels start with peer_window from allocChannel; table starts empty
    try std.testing.expectEqual(@as(u32, 0), session.channel_table.activeCount());
}

test "handlePacket: CHANNEL_OPEN_CONFIRMATION captures initial window" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel so findByLocalId(0) works
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .AutoShell;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(0); // recipient channel
    try pw.writeU32(0); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    const confirmed = m.session.channel_table.findByLocalId(0).?;
    try std.testing.expectEqual(@as(u32, 32768), confirmed.peer_window);
}

test "handlePacket: raw channel confirmation emits ChannelOpened without shell setup" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .RawSession;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expectEqual(@as(u32, 42), chan.remote_id);
    try std.testing.expectEqual(ChannelState.Data, chan.state);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpened => |channel_id| try std.testing.expectEqual(chan.local_id, channel_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try m.clearEvent(.{ .ChannelOpened = chan.local_id });
    try std.testing.expect(std.meta.eql(m.iostate_wr, .Idle));
}

test "handlePacket: direct-tcpip confirmation emits ChannelOpened" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .RawSession;
    chan.channel_type = .DirectTcpip;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(ChannelState.Data, chan.state);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpened => |channel_id| try std.testing.expectEqual(chan.local_id, channel_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: forwarded-tcpip open emits request and accept confirms" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [160]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString("forwarded-tcpip");
    try pw.writeU32(77); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size
    try pw.writeU32LenString("127.0.0.1");
    try pw.writeU32(2222);
    try pw.writeU32LenString("10.0.0.2");
    try pw.writeU32(54321);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    const channel_id = switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpenRequest => |request| blk: {
                switch (request.request) {
                    .ForwardedTcpip => |tcp| {
                        try std.testing.expectEqualStrings("127.0.0.1", tcp.connected_host);
                        try std.testing.expectEqual(@as(u32, 2222), tcp.connected_port);
                        try std.testing.expectEqualStrings("10.0.0.2", tcp.originator_host);
                        try std.testing.expectEqual(@as(u32, 54321), tcp.originator_port);
                    },
                    else => return error.TestUnexpectedResult,
                }
                break :blk request.channel;
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };

    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ChannelType.ForwardedTcpip, chan.channel_type);
    try std.testing.expectEqual(ChannelState.Open, chan.state);

    try m.acceptChannelOpen(channel_id);
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION), try rdr.readU8());
    try std.testing.expectEqual(@as(u32, 77), try rdr.readU32());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
}

test "handlePacket: auto-shell confirmation still emits Connected" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .AutoShell;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(ChannelState.Open, chan.state);

    try m.advance();
    try expectProducedPtyRequest(&m, "xterm-color", 80, 24, 640, 480);
    try m.consumed(m.wr_nbytes);
    try expectProducedChannelRequest(&m, "shell");
    try m.consumed(m.wr_nbytes);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .Connected => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: auto-exec confirmation sends exec without pty by default" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.setAutoExecCommand("printf machine-output");
    _ = try confirmAutoSessionChannel(&m, .AutoExec);

    try m.advance();
    try expectProducedExecRequest(&m, "printf machine-output");
    try m.consumed(m.wr_nbytes);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .Connected => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: auto-exec sends pty then exec when pty setter follows exec" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.setAutoExecCommand("zmx attach default");
    try m.setAutoPty("xterm-ghostty", 123, 45, 984, 720);

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .AutoExec;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(ChannelState.Open, chan.state);

    try m.advance();
    try expectProducedPtyRequest(&m, "xterm-ghostty", 123, 45, 984, 720);
    try m.consumed(m.wr_nbytes);
    try expectProducedExecRequest(&m, "zmx attach default");
    try m.consumed(m.wr_nbytes);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .Connected => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: auto-exec sends latest pty and exec when pty setter comes first" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.setAutoPty("old-term", 80, 24, 640, 480);
    try m.setAutoPty("xterm-new", 132, 50, 1056, 800);
    try m.setAutoExecCommand("false");
    try m.setAutoExecCommand("run-current");
    _ = try confirmAutoSessionChannel(&m, .AutoExec);

    try m.advance();
    try expectProducedPtyRequest(&m, "xterm-new", 132, 50, 1056, 800);
    try m.consumed(m.wr_nbytes);
    try expectProducedExecRequest(&m, "run-current");
}

test "handlePacket: agent forwarding precedes non-pty exec" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.enableAgentForwarding();
    try m.setAutoExecCommand("agent-command");
    _ = try confirmAutoSessionChannel(&m, .AutoExec);

    try m.advance();
    try expectProducedChannelRequest(&m, Protocol.channel_request_auth_agent);
    try m.consumed(m.wr_nbytes);
    try expectProducedExecRequest(&m, "agent-command");
}

test "handlePacket: channel open failure frees channel and emits event" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .RawSession;
    chan.state = .OpenWrite;
    const local_id = chan.local_id;
    try m.session.reserveExitResult(local_id);

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
    try pw.writeU32(local_id); // recipient channel
    try pw.writeU32(4); // SSH_OPEN_RESOURCE_SHORTAGE
    try pw.writeU32LenString("too many channels");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expect(m.session.channel_table.findByLocalId(local_id) == null);
    try std.testing.expect(m.session.findExitResultSlot(local_id) == null);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpenFailure => |failure| {
                try std.testing.expectEqual(local_id, failure.channel);
                try std.testing.expectEqual(@as(u32, 4), failure.reason_code);
                try std.testing.expectEqualStrings("too many channels", failure.description);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: CHANNEL_WINDOW_ADJUST increases peer window" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 1000, 0).?;

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
    try pw.writeU32(0); // channel
    try pw.writeU32(5000); // bytes to add

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(@as(u32, 6000), chan.peer_window);
}

test "handlePacket: SSH_MSG_CHANNEL_EXTENDED_DATA surfaces stderr" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel in DataRx state
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.state = .DataRx;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA));
    try pw.writeU32(0); // channel
    try pw.writeU32(1); // data_type_code = SSH_EXTENDED_DATA_STDERR
    try pw.writeU32LenString("error: something failed\n");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .RxExtendedData => |ext| {
                try std.testing.expectEqual(@as(u32, 0), ext.channel);
                try std.testing.expectEqual(@as(u32, 1), ext.data_type);
                try std.testing.expectEqualStrings("error: something failed\n", ext.data);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "sendWindowChange queues pending change" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    try std.testing.expect(session.pending_window_change == null);
    session.sendWindowChange(120, 40, 960, 640);
    try std.testing.expect(session.pending_window_change != null);
    const wc = session.pending_window_change.?;
    try std.testing.expectEqual(@as(u32, 120), wc[0]);
    try std.testing.expectEqual(@as(u32, 40), wc[1]);
    try std.testing.expectEqual(@as(u32, 960), wc[2]);
    try std.testing.expectEqual(@as(u32, 640), wc[3]);
}

test "a queued window-change is flushed while the channel sits idle" {
    // Regression: the request used to be sent only from the channel's `.Data`
    // pass, which nothing re-enters once a session is established, and the
    // wake-up in sendWindowChange asked findNextRunnable for a channel it
    // reports as not runnable. A terminal resized while nothing was being
    // typed kept its original size for the life of the connection.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.Session, 7, 32768, 32768).?;
    chan.state = .DataRx;
    m.session.sessionState = .ChannelActive;
    m.iostate_wr = .Idle;

    m.session.sendWindowChange(120, 40, 960, 640);
    // Queued only: sending is the transport's job, at a point where it is safe.
    try std.testing.expect(m.session.pending_window_change != null);

    try std.testing.expect(try m.session.flushPendingWindowChange(&m));
    try std.testing.expect(m.session.pending_window_change == null);
    try std.testing.expectEqual(ChannelState.DataRx, chan.state);
}

test "a flushed window-change returns the session to the state it interrupted" {
    // A resize almost always lands while a read is outstanding. Completing the
    // write into `.Idle` would drop the read's completion state on the floor;
    // the packet has to be interjected without disturbing the sequence.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.Session, 7, 32768, 32768).?;
    chan.state = .DataRx;
    m.session.sessionState = .ChannelActive;
    m.iostate_wr = .Idle;
    m.session.setIoSessionState(.ReadPktHdr);

    m.session.sendWindowChange(120, 40, 960, 640);
    try std.testing.expect(try m.session.flushPendingWindowChange(&m));

    switch (m.iostate_wr) {
        .Active => |iotype| try std.testing.expectEqual(
            Protocol.IoSessionState.ReadPktHdr,
            std.meta.activeTag(iotype.next_state),
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "a window-change waits for the write side to be free" {
    // `iobuf_wr` holds exactly one packet, so interjecting a resize into a
    // write already in flight would corrupt it.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.Session, 7, 32768, 32768).?;
    chan.state = .DataRx;
    m.session.sessionState = .ChannelActive;
    m.iostate_wr = .{ .Active = .{ .action = .{ .Producing = 16 }, .next_state = .Idle } };

    m.session.sendWindowChange(120, 40, 960, 640);
    try std.testing.expect(!try m.session.flushPendingWindowChange(&m));
    try std.testing.expect(m.session.pending_window_change != null);
}

test "a window-change is not dispatched onto a closing channel" {
    // The remote end has gone; a request naming its channel would be answered
    // with a failure at best, and the resize is meaningless either way.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.Session, 7, 32768, 32768).?;
    chan.state = .DataRx;
    chan.close_received = true;
    m.session.sessionState = .ChannelActive;
    m.iostate_wr = .Idle;

    m.session.sendWindowChange(120, 40, 960, 640);
    _ = try m.session.flushPendingWindowChange(&m);
    try std.testing.expect(m.session.pending_window_change != null);
}

test "a window-change waits for a session channel to exist" {
    // A resize can arrive before the channel is open, and an agent-forward
    // channel is not the one carrying the terminal.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.AgentForward, 7, 32768, 32768).?;
    chan.state = .DataRx;
    m.session.sessionState = .ChannelActive;
    m.iostate_wr = .Idle;

    m.session.sendWindowChange(120, 40, 960, 640);
    _ = try m.session.flushPendingWindowChange(&m);
    try std.testing.expect(m.session.pending_window_change != null);
}

test "handlePacket: SSH_MSG_USERAUTH_INFO_REQUEST surfaces keyboard-interactive prompt" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setSessionState(.KeyboardInteractiveAuthReq);

    var payload_backing: [256]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK)); // msg 60 = INFO_REQUEST
    try pw.writeU32LenString("Authentication"); // name
    try pw.writeU32LenString("Please enter your password"); // instruction
    try pw.writeU32LenString(""); // language tag
    try pw.writeU32(1); // num-prompts
    try pw.writeU32LenString("Password: "); // prompt
    try pw.writeBoolean(false); // echo

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .KeyboardInteractive => |ki| {
                try std.testing.expectEqualStrings("Authentication", ki.name);
                try std.testing.expectEqualStrings("Please enter your password", ki.instruction);
                try std.testing.expectEqualStrings("Password: ", ki.prompt);
                try std.testing.expect(!ki.echo);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(SessionState.KeyboardInteractiveInfoRsp, m.session.sessionState);
}

test "setKeyboardInteractiveResponse stores response" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    try session.setKeyboardInteractiveResponse("my-password");
    try std.testing.expect(session.kbd_interactive_response != null);
    try std.testing.expectEqualStrings("my-password", session.kbd_interactive_response.?);
}

test "nameListContains finds algorithm in list" {
    try std.testing.expect(Protocol.nameListContains("aes256-ctr,aes128-ctr,aes256-cbc", "aes256-ctr"));
    try std.testing.expect(Protocol.nameListContains("aes256-ctr,aes128-ctr,aes256-cbc", "aes128-ctr"));
    try std.testing.expect(Protocol.nameListContains("aes256-ctr,aes128-ctr,aes256-cbc", "aes256-cbc"));
    try std.testing.expect(Protocol.nameListContains("aes256-ctr", "aes256-ctr"));
}

test "nameListContains rejects missing algorithm" {
    try std.testing.expect(!Protocol.nameListContains("aes128-ctr,aes256-cbc", "aes256-ctr"));
    try std.testing.expect(!Protocol.nameListContains("", "aes256-ctr"));
    try std.testing.expect(!Protocol.nameListContains("aes256-ct", "aes256-ctr"));
}

test "is_rekeying starts false" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();
    try std.testing.expect(!session.is_rekeying);
}

test "client records durable exit status and first terminal result wins" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(77, 32768, 32768).?;
    const channel_id = chan.local_id;
    chan.state = .DataRx;
    try m.session.reserveExitResult(channel_id);
    m.session.setSessionState(.ChannelActive);

    var status_payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &status_payload, 3, .big);
    try deliverChannelRequestForTest(&m, channel_id, Protocol.channel_request_exit_status, true, &status_payload);
    try expectChannelReplyForTest(&m, .SSH_MSG_CHANNEL_SUCCESS, chan.remote_id);

    std.mem.writeInt(u32, &status_payload, 9, .big);
    try deliverChannelRequestForTest(&m, channel_id, Protocol.channel_request_exit_status, false, &status_payload);
    var signal_backing: [64]u8 = undefined;
    var signal = BufferWriter.init(&signal_backing, 0);
    try signal.writeU32LenString("KILL");
    try signal.writeBoolean(false);
    try signal.writeU32LenString("");
    try signal.writeU32LenString("");
    try deliverChannelRequestForTest(&m, channel_id, Protocol.channel_request_exit_signal, false, signal.active());
    switch (m.channelExitResult(channel_id).?) {
        .Status => |status| try std.testing.expectEqual(@as(u32, 3), status),
        else => return error.TestUnexpectedResult,
    }

    chan.close_sent = true;
    var close_payload: [5]u8 = undefined;
    close_payload[0] = @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE);
    std.mem.writeInt(u32, close_payload[1..5], channel_id, .big);
    const close_len = buildUnencryptedPacket(&m.iobuf_rd, &close_payload);
    try m.session.handlePacket(m.iobuf_rd[0..close_len], &m);
    switch (m.channelExitResult(channel_id).?) {
        .Status => |status| try std.testing.expectEqual(@as(u32, 3), status),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(m.clearChannelExitResult(channel_id));
    try expectChannelClosedForTest(&m, channel_id);
    try m.clearEvent(.{ .ChannelClosed = channel_id });
}

test "client owns exit signal fields after receive buffer reuse" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(81, 32768, 32768).?;
    chan.state = .DataRx;
    try m.session.reserveExitResult(chan.local_id);
    m.session.setSessionState(.ChannelActive);

    var signal_backing: [128]u8 = undefined;
    var signal = BufferWriter.init(&signal_backing, 0);
    try signal.writeU32LenString("TERM");
    try signal.writeBoolean(true);
    try signal.writeU32LenString("terminated");
    try signal.writeU32LenString("en-US");
    try deliverChannelRequestForTest(&m, chan.local_id, Protocol.channel_request_exit_signal, false, signal.active());
    @memset(&m.iobuf_rd, 0xa5);

    switch (m.channelExitResult(chan.local_id).?) {
        .Signal => |result| {
            try std.testing.expectEqualStrings("TERM", result.signal_name);
            try std.testing.expect(result.core_dumped);
            try std.testing.expectEqualStrings("terminated", result.error_message);
            try std.testing.expectEqualStrings("en-US", result.language_tag);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "client channel requests reply safely and reject invalid recipients" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const session_chan = m.session.channel_table.allocChannel(91, 32768, 32768).?;
    session_chan.state = .DataRx;
    try m.session.reserveExitResult(session_chan.local_id);
    const tcp_chan = m.session.channel_table.allocChannel(92, 32768, 32768).?;
    tcp_chan.channel_type = .DirectTcpip;
    tcp_chan.state = .DataRx;
    m.session.setSessionState(.ChannelActive);

    try deliverChannelRequestForTest(&m, session_chan.local_id, "unknown@example", true, "opaque");
    try expectChannelReplyForTest(&m, .SSH_MSG_CHANNEL_FAILURE, session_chan.remote_id);
    try deliverChannelRequestForTest(&m, session_chan.local_id, "unknown@example", false, "opaque");

    var status_payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &status_payload, 0, .big);
    try deliverChannelRequestForTest(&m, tcp_chan.local_id, Protocol.channel_request_exit_status, true, &status_payload);
    try expectChannelReplyForTest(&m, .SSH_MSG_CHANNEL_FAILURE, tcp_chan.remote_id);
    try std.testing.expect(m.channelExitResult(tcp_chan.local_id) == null);

    session_chan.close_pending = true;
    try deliverChannelRequestForTest(&m, session_chan.local_id, Protocol.channel_request_exit_status, true, &status_payload);
    try expectChannelReplyForTest(&m, .SSH_MSG_CHANNEL_FAILURE, session_chan.remote_id);
    try std.testing.expect(m.channelExitResult(session_chan.local_id) == null);

    try deliverChannelRequestForTest(&m, 9999, "unknown@example", true, "opaque");
    try std.testing.expectEqual(@as(usize, 0), m.session.pending_channel_replies_len);
}

test "client exit results are isolated and replies retain wire order across rekey" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const first = m.session.channel_table.allocChannel(121, 32768, 32768).?;
    const second = m.session.channel_table.allocChannel(122, 32768, 32768).?;
    first.state = .DataRx;
    second.state = .DataRx;
    try m.session.reserveExitResult(first.local_id);
    try m.session.reserveExitResult(second.local_id);
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);

    var zero: [4]u8 = undefined;
    std.mem.writeInt(u32, &zero, 0, .big);
    try deliverChannelRequestForTest(&m, first.local_id, Protocol.channel_request_exit_status, false, &zero);
    switch (m.channelExitResult(first.local_id).?) {
        .Status => |status| try std.testing.expectEqual(@as(u32, 0), status),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(m.channelExitResult(second.local_id) == null);

    m.session.is_rekeying = true;
    try m.session.queueChannelReply(first.remote_id, false);
    try m.session.queueChannelReply(second.remote_id, true);
    try std.testing.expect(!try m.session.flushPendingChannelReply(&m));
    m.session.is_rekeying = false;

    try std.testing.expect(try m.session.dispatchDeferredChannelWrite(&m));
    try expectChannelReplyForTest(&m, .SSH_MSG_CHANNEL_FAILURE, first.remote_id);
    try expectChannelReplyForTest(&m, .SSH_MSG_CHANNEL_SUCCESS, second.remote_id);
}

test "channel request replies precede deferred data and channel control" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(131, 32768, 32768).?;
    chan.state = .DataRx;
    chan.write_buf[0] = 'x';
    chan.write_buf_nbytes = 1;
    chan.eof_pending = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    try m.session.queueChannelReply(chan.remote_id, false);

    try std.testing.expect(try m.session.dispatchDeferredChannelWrite(&m));
    try expectChannelReplyForTest(&m, .SSH_MSG_CHANNEL_FAILURE, chan.remote_id);

    const data_packet = try m.peek(Protocol.MaxSSHPacket);
    var data_reader = BufferReader.init(unencryptedPayload(data_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA), try data_reader.readU8());
    try std.testing.expectEqual(chan.remote_id, try data_reader.readU32());
    try std.testing.expectEqualStrings("x", try data_reader.readU32LenString());
    try m.consumed(data_packet.len);

    const eof_packet = try m.peek(Protocol.MaxSSHPacket);
    var eof_reader = BufferReader.init(unencryptedPayload(eof_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF), try eof_reader.readU8());
    try std.testing.expectEqual(chan.remote_id, try eof_reader.readU32());
}

test "client exit result reservations provide backpressure and no-result completion" {
    var prng = std.Random.DefaultPrng.init(42);
    const limits = Sshz.ResourceLimits{ .max_channels = 1 };
    var m = try SshzClient.initWithLimits(prng.random(), "testuser", std.testing.allocator, limits);
    defer m.deinit();
    try m.setAutoSessionEnabled(false);

    const first = m.session.channel_table.allocChannel(101, 32768, 32768).?;
    const first_id = first.local_id;
    try m.session.reserveExitResult(first_id);
    first.close_sent = true;
    var close_payload: [5]u8 = undefined;
    close_payload[0] = @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE);
    std.mem.writeInt(u32, close_payload[1..5], first_id, .big);
    const close_len = buildUnencryptedPacket(&m.iobuf_rd, &close_payload);
    m.session.user_authenticated = true;
    try m.session.handlePacket(m.iobuf_rd[0..close_len], &m);
    switch (m.channelExitResult(first_id).?) {
        .NoResult => {},
        else => return error.TestUnexpectedResult,
    }
    try expectChannelClosedForTest(&m, first_id);
    try m.clearEvent(.{ .ChannelClosed = first_id });

    const second = m.session.channel_table.allocChannel(102, 32768, 32768).?;
    try std.testing.expectError(IoError.tooManyChannels, m.session.reserveExitResult(second.local_id));
    try std.testing.expect(m.clearChannelExitResult(first_id));
    try m.session.reserveExitResult(second.local_id);
}

test "client exposes automatic session channel id durably" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setSessionState(.ChannelOpenReq);
    m.session.setIoSessionState(.Idle);
    try m.session.advanceSession(&m);
    const id = m.automaticSessionChannelId().?;
    m.session.completeExitResult(id);
    m.session.channel_table.freeChannel(id);
    try std.testing.expectEqual(id, m.automaticSessionChannelId().?);
}

test "client rejects malformed and trailing terminal channel requests" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(111, 32768, 32768).?;
    chan.state = .DataRx;
    try m.session.reserveExitResult(chan.local_id);
    m.session.setSessionState(.ChannelActive);

    try std.testing.expectError(
        BufferError.ReaderOutOfDataErr,
        deliverChannelRequestForTest(&m, chan.local_id, Protocol.channel_request_exit_status, false, &.{ 0, 0, 0 }),
    );
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        deliverChannelRequestForTest(&m, chan.local_id, Protocol.channel_request_exit_status, false, &.{ 0, 0, 0, 0, 1 }),
    );
    const truncated_signal = [_]u8{ 0, 0, 0, 4, 'T', 'E', 'R', 'M', 0, 0 };
    try std.testing.expectError(
        BufferError.ReaderOutOfDataErr,
        deliverChannelRequestForTest(&m, chan.local_id, Protocol.channel_request_exit_signal, false, &truncated_signal),
    );

    var trailing_signal_backing: [64]u8 = undefined;
    var trailing_signal = BufferWriter.init(&trailing_signal_backing, 0);
    try trailing_signal.writeU32LenString("TERM");
    try trailing_signal.writeBoolean(false);
    try trailing_signal.writeU32LenString("");
    try trailing_signal.writeU32LenString("");
    try trailing_signal.writeU8(1);
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        deliverChannelRequestForTest(
            &m,
            chan.local_id,
            Protocol.channel_request_exit_signal,
            false,
            trailing_signal.active(),
        ),
    );
}
