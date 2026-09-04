const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const UNSAFE_TRACEDUMP = util.unsafeTracedump;
const Sshz = @import("sshz.zig");
const SshzServer = Sshz.SshzServer;
const SshzError = Sshz.SshzError;
const IoError = Sshz.IoError;
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
const ChannelType = @import("channel.zig").ChannelType;
const TcpipOpen = @import("channel.zig").TcpipOpen;

const supported_auth_methods = "password,publickey";

const PendingAuthorizationKind = enum {
    Authentication,
    PublicKeyProbe,
};

pub const SessionState = enum {
    Init,
    KexInitWrite,
    KexInitRead,
    EcdhInitRead,
    EcdhReplyWrite,
    NewKeysRead,
    NewKeysWrite,
    AuthRead,
    AuthRspServReqSuccess,
    CheckUserPasswordAuth,
    UserAuthDenied,
    UserAuthAccepted,
    AuthPkAllowed,
    Authenticated,
    ChannelActive,
};

const PendingGlobalRequestKind = enum {
    TcpipForward,
    CancelTcpipForward,
};

const PendingGlobalRequest = struct {
    kind: PendingGlobalRequestKind,
    want_reply: bool,
    bind_address: []const u8,
    bind_port: u32,
};

pub const Session = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    limits: Sshz.ResourceLimits,
    ioSessionState: Protocol.IoSessionState,
    sessionState: SessionState,

    // Owned only while an ECDH exchange is in progress.
    ecdh_ephem_keypair: Protocol.kex_algo.KeyPair = std.mem.zeroes(Protocol.kex_algo.KeyPair),
    ecdh_ephem_keypair_active: bool,
    shared_secret_k: [Protocol.kex_algo.shared_length]u8 = .{0} ** Protocol.kex_algo.shared_length, // K
    kex_hasher: Hasher(Protocol.hash_algo) = undefined, // for building H
    kex_hash_order: Protocol.KexHashOrder = .Init,
    selected_hostkey_algorithm: ?Key.SignatureAlgorithm,
    session_id: [Protocol.hash_algo.digest_length]u8 = .{0} ** Protocol.hash_algo.digest_length,
    session_id_established: bool = false,
    user_authenticated: bool = false,
    keydata: Protocol.KeyDataBi,
    rand: std.Random = undefined,
    encrypted: bool,
    inbound_encrypted: bool,
    channel_table: ChannelTable,
    active_channel_id: ?u32,
    pending_global_request: ?PendingGlobalRequest,
    pending_global_request_bind_address: [Protocol.MaxSSHPacket]u8 = undefined,
    is_rekeying: bool,
    rekey_resume_state: ?SessionState,
    pending_c2s_keys: ?Protocol.KeyDataUni,
    pending_s2c_keys: ?Protocol.KeyDataUni,
    negotiated_compression_c2s: Protocol.CompressionAlgorithm,
    negotiated_compression_s2c: Protocol.CompressionAlgorithm,
    client_version: ?[]u8,
    server_version: ?[]u8,
    pre_identification_lines: usize,
    ignore_next_kex_packet: bool,
    pending_server_kexinit: ?[]u8,

    auth_pubkey_attempted: Key.Blob,
    auth_pubkey_algorithm: ?Key.SignatureAlgorithm,
    pending_authorization: ?PendingAuthorizationKind,
    q_c: [Protocol.kex_algo.public_length]u8 = .{0} ** Protocol.kex_algo.public_length,

    host_private_key: Key.PrivateKey,
    host_private_key_active: bool,

    pub fn init(rand: std.Random, hostkey_ascii: []const u8, allocator: std.mem.Allocator) !Self {
        return initWithLimits(rand, hostkey_ascii, allocator, .{});
    }

    pub fn initWithLimits(
        rand: std.Random,
        hostkey_ascii: []const u8,
        allocator: std.mem.Allocator,
        limits: Sshz.ResourceLimits,
    ) !Self {
        try limits.validate();
        var s = Self{
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .limits = limits,
            .encrypted = false,
            .inbound_encrypted = false,
            .keydata = Protocol.KeyDataBi.init(),
            .kex_hasher = Hasher(Protocol.hash_algo).init(), // for hashing H
            .selected_hostkey_algorithm = null,
            .ecdh_ephem_keypair_active = false,
            .auth_pubkey_attempted = .{},
            .auth_pubkey_algorithm = null,
            .pending_authorization = null,
            .host_private_key = undefined,
            .host_private_key_active = false,
            .channel_table = ChannelTable{ .limits = limits.channelLimits() },
            .active_channel_id = null,
            .pending_global_request = null,
            .is_rekeying = false,
            .rekey_resume_state = null,
            .pending_c2s_keys = null,
            .pending_s2c_keys = null,
            .negotiated_compression_c2s = .None,
            .negotiated_compression_s2c = .None,
            .client_version = null,
            .server_version = null,
            .pre_identification_lines = 0,
            .ignore_next_kex_packet = false,
            .pending_server_kexinit = null,
        };

        s.host_private_key = try decodeOpenSshPrivateKey(hostkey_ascii, null);
        s.host_private_key_active = true;
        errdefer s.clearHostPrivateKey();
        try s.host_private_key.validate();
        s.server_version = try allocator.dupe(u8, Protocol.version);

        return s;
    }

    pub fn failClosed(self: *Self) void {
        self.clearPendingKeys();
        self.clearAndFreeOptional(&self.pending_server_kexinit);
        self.rekey_resume_state = null;
        self.is_rekeying = false;
        self.auth_pubkey_attempted.clear();
        self.auth_pubkey_algorithm = null;
        self.pending_authorization = null;
        self.channel_table.secureZeroAll();
        self.active_channel_id = null;
        self.pending_global_request = null;
        self.keydata.clear();
        self.clearKexState();
        std.crypto.secureZero(u8, &self.session_id);
        self.session_id_established = false;
        self.user_authenticated = false;
        self.clearHostPrivateKey();
        self.encrypted = false;
        self.inbound_encrypted = false;
    }

    pub fn isActive(self: *const Self) bool {
        return self.sessionState == .Authenticated or self.sessionState == .ChannelActive;
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
        self.clearAndFreeOptional(&self.client_version);
        self.clearAndFreeOptional(&self.server_version);
        self.clearPendingKeys();
        self.clearAndFreeOptional(&self.pending_server_kexinit);
        self.clearKexState();
        std.crypto.secureZero(u8, &self.session_id);
        self.session_id_established = false;
        self.user_authenticated = false;
        self.clearHostPrivateKey();
        self.auth_pubkey_attempted.clear();
        self.auth_pubkey_algorithm = null;
        self.pending_authorization = null;
        self.channel_table.secureZeroAll();
        self.keydata.clear();
    }

    fn clearAndFreeOptional(self: *Self, field: *?[]u8) void {
        if (field.*) |slice| {
            std.crypto.secureZero(u8, slice);
            self.allocator.free(slice);
            field.* = null;
        }
    }

    fn clearEphemeralKeyPair(self: *Self) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.ecdh_ephem_keypair));
        self.ecdh_ephem_keypair_active = false;
    }

    fn clearKexState(self: *Self) void {
        self.clearEphemeralKeyPair();
        std.crypto.secureZero(u8, &self.shared_secret_k);
        std.crypto.secureZero(u8, &self.q_c);
        self.kex_hasher.clear();
    }

    fn clearHostPrivateKey(self: *Self) void {
        if (!self.host_private_key_active) return;
        self.host_private_key.clear();
        self.host_private_key_active = false;
    }

    fn clearAuthAttempt(self: *Self) void {
        self.auth_pubkey_attempted.clear();
        self.auth_pubkey_algorithm = null;
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
        self.clearAndFreeOptional(&self.client_version);
        self.client_version = try self.allocator.dupe(u8, version);
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

    fn startPeerRekey(self: *Self) SshzError!void {
        if (self.is_rekeying) return IoError.UnexpectedResponse;
        self.resetKexHasherForRekey();
        self.clearAndFreeOptional(&self.pending_server_kexinit);
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

    fn installExchangeKeys(self: *Self, kexhash: [Protocol.hash_algo.digest_length]u8) SshzError!void {
        defer std.crypto.secureZero(u8, &self.shared_secret_k);
        if (!self.is_rekeying) {
            @memcpy(&self.session_id, &kexhash);
            self.session_id_established = true;
        } else if (!self.session_id_established) {
            // A re-key can never be the first exchange. Refuse rather than derive
            // keys and bind userauth signatures against an all-zero session_id.
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

    fn activatePendingC2sKeys(self: *Self, sshz: *SshzServer) SshzError!void {
        var next = self.pending_c2s_keys orelse return IoError.UnexpectedResponse;
        self.pending_c2s_keys = null;
        errdefer next.clear();
        next.seq = self.keydata.c2s.seq;
        try next.activateEpoch(self.keydata.c2s.epoch, sshz.keyActivationTime());
        next.compression.applyPendingAlgorithm();
        self.keydata.c2s.clear();
        self.keydata.c2s = next;
        next.clear();
        if (self.is_rekeying) try self.keydata.c2s.compression.activateInflate();
        self.inbound_encrypted = true;
    }

    fn activatePendingS2cKeys(self: *Self, sshz: *SshzServer) SshzError!void {
        var next = self.pending_s2c_keys orelse return IoError.UnexpectedResponse;
        self.pending_s2c_keys = null;
        errdefer next.clear();
        next.seq = self.keydata.s2c.seq;
        try next.activateEpoch(self.keydata.s2c.epoch, sshz.keyActivationTime());
        next.compression.applyPendingAlgorithm();
        self.keydata.s2c.clear();
        self.keydata.s2c = next;
        next.clear();
        if (self.is_rekeying) try self.keydata.s2c.compression.activateDeflate();
        self.encrypted = true;
    }

    pub fn decideAuthorization(
        self: *Self,
        decision: Sshz.AuthorizationDecision,
    ) SshzError!void {
        if (self.sessionState != .CheckUserPasswordAuth) {
            return IoError.UnexpectedResponse;
        }
        const pending = self.pending_authorization orelse return IoError.UnexpectedResponse;
        self.pending_authorization = null;

        switch (decision) {
            .Deny => {
                self.clearAuthAttempt();
                self.setSessionState(.UserAuthDenied);
            },
            .Allow => switch (pending) {
                .Authentication => {
                    self.clearAuthAttempt();
                    self.setSessionState(.UserAuthAccepted);
                },
                .PublicKeyProbe => self.setSessionState(.AuthPkAllowed),
            },
        }
    }

    pub fn grantAccess(self: *Self, allow: bool) SshzError!void {
        return self.decideAuthorization(if (allow) .Allow else .Deny);
    }

    fn denyAuthentication(self: *Self) void {
        self.clearAuthAttempt();
        self.pending_authorization = null;
        self.setSessionState(.UserAuthDenied);
        self.setIoSessionState(.Idle);
    }

    fn activateDelayedCompression(self: *Self) SshzError!void {
        try self.keydata.s2c.compression.activateDeflate();
        try self.keydata.c2s.compression.activateInflate();
    }

    pub fn advanceSession(self: *Self, sshz: *SshzServer) SshzError!void {
        const outkeys = &self.keydata.s2c;

        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitRead);
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .KexInitWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
                var cookie: [16]u8 = undefined;
                self.rand.bytes(&cookie);
                try pkt.writeBytes(&cookie);

                const offers = Protocol.localAlgorithmOffers(self.host_private_key.hostKeyAlgorithms());
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

                if (self.kex_hash_order == .I_C) {
                    self.kex_hash_order = self.kex_hash_order.check(.I_S);
                    self.kex_hasher.writeU32LenString(pkt.active());
                } else if (self.kex_hash_order == .V_S and self.is_rekeying) {
                    if (self.pending_server_kexinit != null) return IoError.UnexpectedResponse;
                    self.pending_server_kexinit = try self.allocator.dupe(u8, pkt.active());
                } else {
                    return IoError.UnexpectedResponse;
                }

                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
                self.setSessionState(if (self.kex_hash_order == .I_S) .EcdhInitRead else .KexInitRead);
            },
            .EcdhInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhReplyWrite => {
                errdefer self.clearKexState();
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);

                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY));

                var hostkey_blob_buf: Key.Blob = .{};
                const hostkey_blob = try self.host_private_key.publicBlob(&hostkey_blob_buf);

                UNSAFE_TRACEDUMP(.Debug, "ks", .{}, hostkey_blob);
                self.kex_hash_order = self.kex_hash_order.check(.K_S);
                self.kex_hasher.writeU32LenString(hostkey_blob);
                try pkt.writeU32LenString(hostkey_blob);

                self.kex_hash_order = self.kex_hash_order.check(.Q_C);
                self.kex_hasher.writeU32LenString(&self.q_c);

                var seed: [Protocol.kex_algo.seed_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &seed);
                self.rand.bytes(&seed);
                self.clearEphemeralKeyPair();
                self.ecdh_ephem_keypair = Protocol.kex_algo.KeyPair.generateDeterministic(seed) catch unreachable;
                self.ecdh_ephem_keypair_active = true;
                try pkt.writeU32LenString(&self.ecdh_ephem_keypair.public_key);
                UNSAFE_TRACEDUMP(.Debug, "qs", .{}, &self.ecdh_ephem_keypair.public_key);

                self.kex_hash_order = self.kex_hash_order.check(.Q_S);
                self.kex_hasher.writeU32LenString(&self.ecdh_ephem_keypair.public_key);

                // generate shared secret
                var shared_secret = try Protocol.kex_algo.scalarmult(
                    self.ecdh_ephem_keypair.secret_key,
                    self.q_c,
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

                const sig_alg = self.selected_hostkey_algorithm orelse self.host_private_key.defaultSignatureAlgorithm();
                var typed_sig: Key.SignatureBlob = .{};
                defer typed_sig.clear();
                const sig = try self.host_private_key.sign(sig_alg, &kexhash, &typed_sig);
                try pkt.writeU32LenString(sig);

                try self.installExchangeKeys(kexhash);
                self.clearKexState();

                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);

                self.setSessionState(.NewKeysWrite);
            },
            .NewKeysWrite => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr);
                try sshz.requestWrite(wrapped, .Idle);
                try self.activatePendingS2cKeys(sshz);
                self.setSessionState(.NewKeysRead);
            },
            .NewKeysRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthRspServReqSuccess => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_ACCEPT));
                try pkt.writeU32LenString("ssh-userauth");
                self.setSessionState(.AuthRead);
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .CheckUserPasswordAuth => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .UserAuthDenied => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE));
                try pkt.writeU32LenString(supported_auth_methods);
                try pkt.writeBoolean(false); // partial success
                self.setSessionState(.AuthRead);
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .UserAuthAccepted => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS));
                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr);
                try self.activateDelayedCompression();
                self.user_authenticated = true;
                self.setSessionState(.Authenticated);
                try sshz.requestWrite(wrapped, .Idle);
            },
            .AuthPkAllowed => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK));
                const auth_alg = self.auth_pubkey_algorithm orelse return IoError.UnexpectedResponse;
                try pkt.writeU32LenString(auth_alg.name());
                try pkt.writeU32LenString(self.auth_pubkey_attempted.slice());
                self.clearAuthAttempt();
                self.setSessionState(.AuthRead);
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .Authenticated => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelActive => {
                try self.advanceChannel(sshz, outkeys);
            },
        }
    }

    fn advanceChannel(self: *Self, sshz: *SshzServer, outkeys: *Protocol.KeyDataUni) SshzError!void {
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
            var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
            try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
            try pkt.writeU32(chan.remote_id);
            const adjust = chan.windowAdjustAmount();
            try pkt.writeU32(adjust);
            chan.local_window = chan.local_window_target;
            try sshz.requestWrite(
                try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr),
                .WriteCompletePreserveState,
            );
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
                try pkt.writeU32LenString(chan.channel_type.name());
                try pkt.writeU32(chan.local_id);
                try pkt.writeU32(self.limits.initial_channel_window);
                try pkt.writeU32(self.limits.channel_packet_size);
                if (chan.channel_type.hasTcpipOpenPayload()) {
                    try pkt.writeU32LenString(chan.tcpip_open.host);
                    try pkt.writeU32(chan.tcpip_open.port);
                    try pkt.writeU32LenString(chan.tcpip_open.originator_host);
                    try pkt.writeU32(chan.tcpip_open.originator_port);
                }
                chan.state = .Open;
                self.active_channel_id = null;
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .ReadPktHdr);
            },
            .ConfirmWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(chan.local_id);
                try pkt.writeU32(self.limits.initial_channel_window);
                try pkt.writeU32(self.limits.channel_packet_size);
                chan.state = if (chan.channel_type == .Session) .Connected else .Data;
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .OpenFailureWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(chan.open_failure_reason_code);
                try pkt.writeU32LenString(chan.open_failure_description);
                try pkt.writeU32LenString("");
                self.channel_table.freeChannel(chan.local_id);
                self.active_channel_id = null;
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .RspWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_SUCCESS));
                try pkt.writeU32(chan.remote_id);
                chan.state = .Data;
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .RspFailureWrite => {
                var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_FAILURE));
                try pkt.writeU32(chan.remote_id);
                chan.state = .Data;
                try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .Idle);
            },
            .Connected => {
                sshz.requestEvent(.{ .Connected = chan.local_id }, .Idle);
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
                self.channel_table.freeChannel(local_id);
                self.active_channel_id = null;
                if (kind == .AgentForward) {
                    sshz.requestEvent(.{ .AgentChannelClosed = local_id }, .ReadPktHdr);
                } else if (self.channel_table.activeCount() == 0) {
                    sshz.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .Open => {
                if (chan.kind == .AgentForward) {
                    var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
                    try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
                    try pkt.writeU32LenString(Protocol.channel_type_auth_agent_openssh);
                    try pkt.writeU32(chan.local_id);
                    try pkt.writeU32(self.limits.initial_channel_window);
                    try pkt.writeU32(self.limits.channel_packet_size);
                    chan.state = .OpenSent;
                    try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &sshz.iobuf_wr), .ReadPktHdr);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .OpenSent => {
                self.setIoSessionState(.ReadPktHdr);
            },
        }
    }

    pub fn acceptChannelOpen(self: *Self, channel_id: u32) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.state != .Open) return IoError.UnexpectedResponse;
        chan.state = .ConfirmWrite;
        self.active_channel_id = channel_id;
        self.resumeChannelActive();
        self.setIoSessionState(.Idle);
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

    pub fn openForwardedTcpipChannel(
        self: *Self,
        sshz: *SshzServer,
        connected_host: []const u8,
        connected_port: u32,
        originator_host: []const u8,
        originator_port: u32,
    ) SshzError!u32 {
        if (sshz.iostate_wr != .Idle or self.active_channel_id != null) {
            return IoError.cannotAcceptWrite;
        }
        if (self.sessionState != .Authenticated and self.sessionState != .ChannelActive) {
            return IoError.NotReady;
        }

        const chan = self.channel_table.allocOutboundChannel() orelse return IoError.tooManyChannels;
        chan.channel_type = .ForwardedTcpip;
        chan.tcpip_open = .{
            .host = connected_host,
            .port = connected_port,
            .originator_host = originator_host,
            .originator_port = originator_port,
        };
        chan.state = .OpenWrite;
        self.active_channel_id = chan.local_id;
        self.resumeChannelActive();
        self.setIoSessionState(.Idle);
        try self.advanceChannel(sshz, &self.keydata.s2c);
        return chan.local_id;
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
    pub fn directChannelWrite(self: *Self, channel_id: u32, nbytes: usize, sshz: *SshzServer) SshzError!void {
        const chan = try self.queueChannelWrite(channel_id, nbytes);
        _ = try self.startChannelWrite(chan, sshz, &self.keydata.s2c);
    }

    fn startChannelWrite(
        self: *Self,
        chan: *Channel,
        sshz: *SshzServer,
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

    pub fn completeChannelWrite(self: *Self, channel_id: u32, sshz: *SshzServer) SshzError!void {
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
            const queued = try self.startPendingChannelControl(chan, sshz, &self.keydata.s2c);
            if (!queued) _ = try self.dispatchDeferredChannelWrite(sshz);
            return;
        }
        var queued = false;
        if (chan.write_buf_nbytes > 0) {
            queued = try self.startChannelWrite(chan, sshz, &self.keydata.s2c);
        } else {
            queued = try self.startPendingChannelControl(chan, sshz, &self.keydata.s2c);
        }
        if (!queued) _ = try self.dispatchDeferredChannelWrite(sshz);
    }

    fn startPendingChannelControl(
        self: *Self,
        chan: *Channel,
        sshz: *SshzServer,
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

    pub fn dispatchDeferredChannelWrite(self: *Self, sshz: *SshzServer) SshzError!bool {
        if (self.sessionState != .ChannelActive or self.is_rekeying or sshz.local_rekey_pending or
            sshz.iostate_wr != .Idle) return false;
        for (0..MaxChannels) |_| {
            const chan = self.channel_table.findNextDeferredWrite() orelse return false;
            if ((chan.close_received or chan.close_pending) and chan.tx_in_flight_len == 0) {
                chan.discardWriteBuffer();
                chan.eof_pending = false;
            }
            if (!chan.eof_sent and !chan.close_sent and !chan.close_pending and !chan.close_received and
                chan.write_buf_nbytes > 0 and chan.tx_in_flight_len == 0 and chan.peer_window > 0)
            {
                return try self.startChannelWrite(chan, sshz, &self.keydata.s2c);
            }
            if (chan.write_buf_nbytes == 0 and chan.tx_in_flight_len == 0) {
                if (try self.startPendingChannelControl(chan, sshz, &self.keydata.s2c)) return true;
            }
        }
        return false;
    }

    pub fn completeChannelControl(self: *Self, channel_id: u32, sshz: *SshzServer) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        const control = chan.control_in_flight orelse return IoError.UnexpectedResponse;
        chan.control_in_flight = null;
        if (control == .Close) {
            if (chan.close_received) {
                chan.state = .Closed;
                self.active_channel_id = chan.local_id;
                self.resumeChannelActive();
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
            const queued = try self.startPendingChannelControl(chan, sshz, &self.keydata.s2c);
            if (!queued) _ = try self.dispatchDeferredChannelWrite(sshz);
        }
    }

    pub fn sendChannelEof(self: *Self, channel_id: u32, sshz: *SshzServer) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent or chan.eof_pending) return;
        if (chan.close_sent or chan.close_pending or chan.close_received) return IoError.UnexpectedResponse;
        chan.eof_pending = true;
        _ = try self.startPendingChannelControl(chan, sshz, &self.keydata.s2c);
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

    pub fn sendChannelClose(self: *Self, channel_id: u32, sshz: *SshzServer) SshzError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.close_sent or chan.close_pending) return;
        chan.close_pending = true;
        chan.eof_pending = false;
        if (chan.tx_in_flight_len == 0) chan.discardWriteBuffer();
        _ = try self.startPendingChannelControl(chan, sshz, &self.keydata.s2c);
    }

    pub fn openAgentChannel(self: *Self) SshzError!u32 {
        const chan = self.channel_table.allocOutboundChannelKind(.AgentForward) orelse return IoError.UnexpectedResponse;
        chan.state = .Open;
        self.active_channel_id = chan.local_id;
        self.resumeChannelActive();
        self.setIoSessionState(.Idle);
        return chan.local_id;
    }

    // special case as we write direct to stream before entering binary pkt mode
    pub fn writeProtocolVersion(self: *Self, buf: []u8) []const u8 {
        const server_version = self.server_version.?;
        const vers = std.fmt.bufPrint(buf, "{s}\r\n", .{server_version}) catch unreachable;
        TRACE(.Debug, "TX: version '{s}'", .{server_version});
        self.kex_hash_order = self.kex_hash_order.check(.V_S);
        self.kex_hasher.writeU32LenString(server_version);
        return vers;
    }

    fn sendChannelOpenFailure(
        self: *Self,
        sshz: *SshzServer,
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
        try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.s2c, &pkt, &sshz.iobuf_wr), .Idle);
    }

    fn sendGlobalRequestSuccess(
        self: *Self,
        sshz: *SshzServer,
        include_bound_port: bool,
        bound_port: u32,
    ) SshzError!void {
        if (sshz.iostate_wr != .Idle) return IoError.cannotAcceptWrite;

        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS));
        if (include_bound_port) {
            try pkt.writeU32(bound_port);
        }
        try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.s2c, &pkt, &sshz.iobuf_wr), .ReadPktHdr);
    }

    fn sendGlobalRequestFailure(self: *Self, sshz: *SshzServer) SshzError!void {
        if (sshz.iostate_wr != .Idle) return IoError.cannotAcceptWrite;

        var pkt = BufferWriter.init(&sshz.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE));
        try sshz.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.s2c, &pkt, &sshz.iobuf_wr), .ReadPktHdr);
    }

    pub fn acceptTcpipForward(self: *Self, sshz: *SshzServer, bound_port: u32) SshzError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        if (pending.kind != .TcpipForward) return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        if (!pending.want_reply) {
            self.setIoSessionState(.ReadPktHdr);
            return;
        }
        try self.sendGlobalRequestSuccess(sshz, pending.bind_port == 0, bound_port);
    }

    pub fn rejectTcpipForward(self: *Self, sshz: *SshzServer) SshzError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        if (pending.kind != .TcpipForward) return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        if (!pending.want_reply) {
            self.setIoSessionState(.ReadPktHdr);
            return;
        }
        try self.sendGlobalRequestFailure(sshz);
    }

    pub fn acceptCancelTcpipForward(self: *Self, sshz: *SshzServer) SshzError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        if (pending.kind != .CancelTcpipForward) return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        if (!pending.want_reply) {
            self.setIoSessionState(.ReadPktHdr);
            return;
        }
        try self.sendGlobalRequestSuccess(sshz, false, 0);
    }

    pub fn rejectCancelTcpipForward(self: *Self, sshz: *SshzServer) SshzError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        if (pending.kind != .CancelTcpipForward) return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        if (!pending.want_reply) {
            self.setIoSessionState(.ReadPktHdr);
            return;
        }
        try self.sendGlobalRequestFailure(sshz);
    }

    fn readTcpipOpen(rdr: *BufferReader) SshzError!TcpipOpen {
        return .{
            .host = try rdr.readU32LenString(),
            .port = try rdr.readU32(),
            .originator_host = try rdr.readU32LenString(),
            .originator_port = try rdr.readU32(),
        };
    }

    fn isSessionChannelRequest(request_name: []const u8) bool {
        return std.mem.eql(u8, request_name, "pty-req") or
            std.mem.eql(u8, request_name, "x11-req") or
            std.mem.eql(u8, request_name, "shell") or
            std.mem.eql(u8, request_name, "exec") or
            std.mem.eql(u8, request_name, "subsystem") or
            std.mem.eql(u8, request_name, "env") or
            std.mem.eql(u8, request_name, Protocol.channel_request_auth_agent) or
            std.mem.eql(u8, request_name, "window-change") or
            std.mem.eql(u8, request_name, "xon-xoff") or
            std.mem.eql(u8, request_name, "signal") or
            std.mem.eql(u8, request_name, "exit-status") or
            std.mem.eql(u8, request_name, "exit-signal") or
            std.mem.eql(u8, request_name, "break");
    }

    fn requestChannelOpenEvent(self: *Self, sshz: *SshzServer, chan: *Channel) void {
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

    fn handleChannelOpenPacket(self: *Self, rdr: *BufferReader, sshz: *SshzServer) SshzError!void {
        if (self.sessionState != .Authenticated and self.sessionState != .ChannelActive) {
            return IoError.UnexpectedResponse;
        }

        // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
        const chantype = try rdr.readU32LenString();
        const remote_id = try rdr.readU32();
        const peer_window = try rdr.readU32();
        const max_packet_size = try rdr.readU32();
        try self.validatePeerChannel(peer_window, max_packet_size);
        const channel_type = ChannelType.fromName(chantype) orelse {
            try self.sendChannelOpenFailure(
                sshz,
                remote_id,
                SshOpenFailureReason.UnknownChannelType,
                "unknown channel type",
            );
            return;
        };
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

        chan.state = .Open;
        self.active_channel_id = null;
        self.resumeChannelActive();
        self.requestChannelOpenEvent(sshz, chan);
    }

    fn handleGlobalRequestPacket(self: *Self, rdr: *BufferReader, sshz: *SshzServer) SshzError!void {
        const request_name = try rdr.readU32LenString();
        const want_reply = try rdr.readBoolean();

        if (std.mem.eql(u8, request_name, "tcpip-forward") or std.mem.eql(u8, request_name, "cancel-tcpip-forward")) {
            if (self.pending_global_request != null) {
                if (want_reply) {
                    try self.sendGlobalRequestFailure(sshz);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
                return;
            }

            const bind_address = try rdr.readU32LenString();
            const bind_port = try rdr.readU32();
            if (bind_address.len > self.pending_global_request_bind_address.len) {
                return IoError.tooBig;
            }
            @memcpy(self.pending_global_request_bind_address[0..bind_address.len], bind_address);
            const stored_bind_address = self.pending_global_request_bind_address[0..bind_address.len];

            const kind: PendingGlobalRequestKind = if (std.mem.eql(u8, request_name, "tcpip-forward"))
                .TcpipForward
            else
                .CancelTcpipForward;

            self.pending_global_request = .{
                .kind = kind,
                .want_reply = want_reply,
                .bind_address = stored_bind_address,
                .bind_port = bind_port,
            };
            const event = Sshz.TcpipForwardRequest{
                .bind_address = stored_bind_address,
                .bind_port = bind_port,
            };
            switch (kind) {
                .TcpipForward => sshz.requestEvent(.{ .TcpipForward = event }, .Idle),
                .CancelTcpipForward => sshz.requestEvent(.{ .CancelTcpipForward = event }, .Idle),
            }
            return;
        }

        if (want_reply) {
            try self.sendGlobalRequestFailure(sshz);
        } else {
            self.setIoSessionState(.ReadPktHdr);
        }
    }

    fn handleChannelOpenConfirmationPacket(self: *Self, rdr: *BufferReader, sshz: *SshzServer) SshzError!void {
        const recipient = try rdr.readU32();
        const sender = try rdr.readU32();
        const peer_window = try rdr.readU32();
        const max_packet_size = try rdr.readU32();
        try self.validatePeerChannel(peer_window, max_packet_size);
        if (self.channel_table.findByLocalId(recipient)) |chan| {
            if (chan.kind == .AgentForward) {
                if (chan.state != .OpenSent) return IoError.UnexpectedResponse;
                chan.remote_id = sender;
                chan.remote_id_known = true;
                chan.peer_window = peer_window;
                chan.remote_max_packet_size = max_packet_size;
                chan.state = .Data;
                self.active_channel_id = null;
                self.resumeChannelActive();
                sshz.requestEvent(.{ .AgentChannelOpen = chan.local_id }, .ReadPktHdr);
                return;
            }

            chan.remote_id = sender;
            chan.remote_id_known = true;
            chan.peer_window = peer_window;
            chan.remote_max_packet_size = max_packet_size;
            chan.state = .Data;
            self.active_channel_id = chan.local_id;
            self.resumeChannelActive();
            sshz.requestEvent(.{ .ChannelOpened = chan.local_id }, .Idle);
        } else {
            self.setIoSessionState(.ReadPktHdr);
        }
    }

    fn handleChannelOpenFailurePacket(self: *Self, rdr: *BufferReader, sshz: *SshzServer) SshzError!void {
        const recipient = try rdr.readU32();
        const reason_code = try rdr.readU32();
        const description = try rdr.readU32LenString();
        _ = try rdr.readU32LenString(); // language tag

        if (self.channel_table.findByLocalId(recipient)) |chan| {
            const local_id = chan.local_id;
            if (chan.kind == .AgentForward and chan.state == .OpenSent) {
                self.channel_table.freeChannel(local_id);
                self.active_channel_id = null;
                sshz.requestEvent(.{ .AgentChannelClosed = local_id }, .ReadPktHdr);
                return;
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
    }

    /// RFC 4250 §4.1.2 reserves message numbers 80-127 for the connection
    /// protocol, which is only reachable after `ssh-userauth` succeeds. This is
    /// a latch rather than a `sessionState` test because RFC 4253 §9 allows
    /// connection-protocol packets sent before a re-key to still arrive while
    /// `sessionState` is temporarily back in the key-exchange states.
    fn isAuthenticatedForConnectionProtocol(self: *const Self) bool {
        return self.user_authenticated;
    }

    pub fn handlePacket(self: *Self, buf: []const u8, sshz: *SshzServer) SshzError!void {
        var rdr = try sshz.getRecvBuffer(sshz.iobuf_rd[0..buf.len], &self.keydata.c2s);

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
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT) => {
                errdefer self.clearKexState();
                TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                // A peer-initiated re-key is only meaningful once the first key
                // exchange has completed. Without this, a KEXINIT arriving
                // mid-initial-handshake is misclassified as a re-key, which
                // leaves session_id all-zero and can drive kex_hash_order into
                // an illegal transition.
                const initial_kex = self.sessionState == .KexInitRead and !self.is_rekeying and
                    !self.encrypted and !self.inbound_encrypted;
                const local_or_simultaneous_rekey = self.sessionState == .KexInitRead and self.is_rekeying;
                const peer_initiated_rekey = !initial_kex and !local_or_simultaneous_rekey;
                if (peer_initiated_rekey) {
                    if (!self.session_id_established) return IoError.UnexpectedResponse;
                    TRACE(.Info, "Re-keying initiated by peer", .{});
                    try self.startPeerRekey();
                }

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(rdr.payload[(rdr.off - 1)..]); // from before the msgid

                // RFC 4253 §7.1: the peer client controls preference ordering.
                const peer_kexinit = try Protocol.readKexInit(&rdr);
                const negotiated = try Protocol.negotiateAlgorithms(
                    peer_kexinit,
                    .Server,
                    self.host_private_key.hostKeyAlgorithms(),
                );
                self.selected_hostkey_algorithm = Key.SignatureAlgorithm.fromName(negotiated.host_key) orelse
                    return IoError.AlgorithmNegotiationFailed;
                self.negotiated_compression_c2s = negotiated.compression_c2s;
                self.negotiated_compression_s2c = negotiated.compression_s2c;
                self.ignore_next_kex_packet = negotiated.ignore_next_peer_packet;

                if (local_or_simultaneous_rekey) {
                    const local_kexinit = self.pending_server_kexinit orelse
                        return IoError.UnexpectedResponse;
                    self.kex_hash_order = self.kex_hash_order.check(.I_S);
                    self.kex_hasher.writeU32LenString(local_kexinit);
                    self.clearAndFreeOptional(&self.pending_server_kexinit);
                    self.setSessionState(.EcdhInitRead);
                    self.setIoSessionState(.ReadPktHdr);
                } else if (initial_kex or peer_initiated_rekey) {
                    self.setSessionState(.KexInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT) => {
                if (self.sessionState == .EcdhInitRead) {
                    errdefer self.clearKexState();
                    const q_c = try rdr.readU32LenString();
                    if (q_c.len != Protocol.kex_algo.public_length) {
                        return IoError.UnexpectedResponse;
                    }
                    if (rdr.off != rdr.payload.len) return IoError.UnexpectedResponse;
                    UNSAFE_TRACEDUMP(.Debug, "q_c", .{}, q_c);
                    @memcpy(&self.q_c, q_c);

                    self.setSessionState(.EcdhReplyWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS) => {
                if (self.sessionState == .NewKeysRead) {
                    try self.activatePendingC2sKeys(sshz);
                    if (self.is_rekeying) {
                        const resume_state = self.rekey_resume_state orelse .ChannelActive;
                        self.is_rekeying = false;
                        self.rekey_resume_state = null;
                        self.setSessionState(resume_state);
                        self.setIoSessionState(.Idle);
                    } else {
                        self.setSessionState(.AuthRead);
                        self.setIoSessionState(.ReadPktHdr);
                    }
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_REQUEST) => {
                if (self.sessionState == .AuthRead) {
                    const svcname = try rdr.readU32LenString();
                    if (std.mem.eql(u8, svcname, "ssh-userauth")) {
                        self.setSessionState(.AuthRspServReqSuccess);
                        self.setIoSessionState(.Idle);
                    } else {
                        return IoError.UnimplementedService;
                    }
                } else {
                    return IoError.UnexpectedResponse; // why is client asking now?
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST) => {
                if (self.sessionState == .AuthRead) {
                    self.clearAuthAttempt();
                    self.pending_authorization = null;
                    errdefer self.clearAuthAttempt();
                    //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                    //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                    const username = try rdr.readU32LenString();
                    const svcname = try rdr.readU32LenString();
                    const authtyp = try rdr.readU32LenString();

                    TRACE(.Debug, "svcname={s} authtyp={s}", .{ svcname, authtyp });
                    if (!std.mem.eql(u8, svcname, "ssh-connection")) {
                        return IoError.UnimplementedService;
                    }

                    if (std.mem.eql(u8, authtyp, "password")) {
                        const password_change = try rdr.readBoolean();
                        const password = try rdr.readU32LenString();
                        if (password_change) {
                            _ = try rdr.readU32LenString(); // new password
                            self.denyAuthentication();
                            return;
                        }
                        self.pending_authorization = .Authentication;
                        self.setSessionState(.CheckUserPasswordAuth);
                        sshz.requestEvent(.{ .UserAuth = .{
                            .username = username,
                            .auth = .{ .Password = password },
                        } }, .Idle);
                    } else if (std.mem.eql(u8, authtyp, "publickey")) {
                        const forreal = try rdr.readBoolean();
                        const algoname = try rdr.readU32LenString();
                        const typed_pubkey = try rdr.readU32LenString();

                        TRACE(.Debug, "forreal={any} algoname={s} typed_pubkey len={d}", .{ forreal, algoname, typed_pubkey.len });

                        const auth_alg = Key.SignatureAlgorithm.fromName(algoname) orelse {
                            self.denyAuthentication();
                            return;
                        };
                        const pubkey = parsePublicKeyBlobExact(typed_pubkey) catch {
                            self.denyAuthentication();
                            return;
                        };
                        if (auth_alg.keyAlgorithm() != pubkey.algorithm()) {
                            self.denyAuthentication();
                            return;
                        }
                        try self.auth_pubkey_attempted.set(typed_pubkey);
                        self.auth_pubkey_algorithm = auth_alg;

                        if (!forreal) {
                            self.pending_authorization = .PublicKeyProbe;
                            self.setSessionState(.CheckUserPasswordAuth);
                            sshz.requestEvent(.{ .UserAuth = .{
                                .username = username,
                                .auth = .{ .Pubkey = .{ .algorithm = algoname, .blob = typed_pubkey } },
                            } }, .Idle);
                        } else {
                            const typedsig = try rdr.readU32LenString();
                            defer std.crypto.secureZero(u8, @constCast(typedsig));
                            const sig_alg = signatureAlgorithmExact(typedsig) orelse {
                                self.denyAuthentication();
                                return;
                            };
                            if (sig_alg != auth_alg) {
                                self.denyAuthentication();
                                return;
                            }

                            var backing_sigbuffer_buf: [1024]u8 = undefined;
                            defer std.crypto.secureZero(u8, &backing_sigbuffer_buf);
                            var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                            try sigbuffer.writeU32LenString(&self.session_id);
                            try sigbuffer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                            try sigbuffer.writeU32LenString(username);
                            try sigbuffer.writeU32LenString("ssh-connection");
                            try sigbuffer.writeU32LenString("publickey");
                            try sigbuffer.writeBoolean(true);
                            try sigbuffer.writeU32LenString(algoname);
                            try sigbuffer.writeU32LenString(typed_pubkey);

                            UNSAFE_TRACEDUMP(.Debug, "typed_pubkey", .{}, typed_pubkey);

                            // verify sig, as provided by user
                            Key.verifySignature(pubkey, typedsig, sigbuffer.payload) catch {
                                TRACE(.Info, "pubkey sig verify failed", .{});
                                self.denyAuthentication();
                                return;
                            };

                            // sig verify ok, confirm with app that this username+pubkey is allowed
                            self.pending_authorization = .Authentication;
                            self.setSessionState(.CheckUserPasswordAuth);
                            sshz.requestEvent(.{ .UserAuth = .{
                                .username = username,
                                .auth = .{ .Pubkey = .{ .algorithm = algoname, .blob = typed_pubkey } },
                            } }, .Idle);
                        }
                    } else if (std.mem.eql(u8, authtyp, "none")) {
                        self.pending_authorization = .Authentication;
                        self.setSessionState(.CheckUserPasswordAuth);
                        sshz.requestEvent(.{ .UserAuth = .{ .username = username, .auth = null } }, .Idle);
                    } else if (std.mem.eql(u8, authtyp, "keyboard-interactive")) {
                        // RFC 4256 requires an information-request/response
                        // exchange. Until that state machine exists, parse the
                        // initial request completely and reject it.
                        _ = try rdr.readU32LenString(); // language tag
                        _ = try rdr.readU32LenString(); // submethods
                        self.denyAuthentication();
                    } else {
                        self.denyAuthentication();
                    }
                } else {
                    return IoError.UnexpectedResponse; // why is client asking now?
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST) => {
                try self.handleGlobalRequestPacket(&rdr, sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN) => {
                try self.handleChannelOpenPacket(&rdr, sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                try self.handleChannelOpenConfirmationPacket(&rdr, sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                try self.handleChannelOpenFailurePacket(&rdr, sshz);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                const recipient = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(recipient) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                const typ = try rdr.readU32LenString();
                const wantreply = try rdr.readBoolean();
                if (chan.channel_type != .Session and isSessionChannelRequest(typ)) {
                    self.active_channel_id = chan.local_id;
                    chan.state = if (wantreply) .RspFailureWrite else .Data;
                    self.resumeChannelActive();
                    self.setIoSessionState(.Idle);
                    return;
                }
                if (std.mem.eql(u8, typ, "pty-req")) {
                    const term = try rdr.readU32LenString();
                    const cols = try rdr.readU32();
                    const rows = try rdr.readU32();
                    const widthpx = try rdr.readU32();
                    const heightpx = try rdr.readU32();

                    _ = term;
                    _ = cols;
                    _ = rows;
                    _ = widthpx;
                    _ = heightpx;
                } else if (std.mem.eql(u8, typ, "shell")) {
                    // RFC 4254 §6.5 — interactive shell
                    sshz.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .Shell } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "exec")) {
                    // RFC 4254 §6.5 — single command execution
                    const command = try rdr.readU32LenString();
                    sshz.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .{ .Exec = command } } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "subsystem")) {
                    // RFC 4254 §6.5 — named subsystem (e.g. sftp)
                    const subsystem = try rdr.readU32LenString();
                    sshz.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .{ .Subsystem = subsystem } } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "env")) {
                    // RFC 4254 §6.4 — set environment variable
                    const name = try rdr.readU32LenString();
                    const value = try rdr.readU32LenString();
                    sshz.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .{ .Env = .{ .name = name, .value = value } } } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, Protocol.channel_request_auth_agent)) {
                    sshz.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .AgentForward } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "window-change")) {
                    // RFC 4254 §6.7
                    const cols = try rdr.readU32();
                    const rows = try rdr.readU32();
                    const widthpx = try rdr.readU32();
                    const heightpx = try rdr.readU32();
                    sshz.requestEvent(.{ .WindowChange = .{
                        .channel = chan.local_id,
                        .cols = cols,
                        .rows = rows,
                        .width_px = widthpx,
                        .height_px = heightpx,
                    } }, .Idle);
                    return;
                } else if (std.mem.eql(u8, typ, "signal")) {
                    // RFC 4254 §6.9
                    const signal_name = try rdr.readU32LenString();
                    sshz.requestEvent(.{ .Signal = .{ .channel = chan.local_id, .name = signal_name } }, .Idle);
                    return;
                } else {
                    TRACE(.Debug, "channel req '{s}'", .{typ});
                    if (wantreply) { // can't do this
                        return IoError.UnimplementedService;
                    }
                }

                if (wantreply) {
                    self.active_channel_id = chan.local_id;
                    chan.state = .RspWrite;
                    self.resumeChannelActive();
                    self.setIoSessionState(.Idle);
                } else {
                    chan.state = .Data;
                    self.resumeChannelActive();
                    self.setIoSessionState(.Idle);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                if (chan.eof_received) {
                    // Peer sent EOF then data — protocol violation, silently discard
                    TRACE(.Debug, "discarding data after EOF on channel {d}", .{channelnum});
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                }
                if (chan.state != .DataRx) {
                    return IoError.UnexpectedResponse;
                }
                const s = try rdr.readU32LenString();
                try chan.consumeLocalWindow(s.len);
                sshz.requestEvent(.{ .RxData = .{ .channel = chan.local_id, .data = s } }, .Idle);
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
                try chan.consumeLocalWindow(s.len);
                sshz.requestEvent(.{ .RxExtendedData = .{ .channel = chan.local_id, .data_type = data_type, .data = s } }, .Idle);
                chan.state = .Data;
                self.active_channel_id = chan.local_id;
                self.resumeChannelActive();
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
                    chan.eof_received = true;
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
                    if (chan.kind == .AgentForward) {
                        self.active_channel_id = chan.local_id;
                        chan.state = .Closed;
                        self.resumeChannelActive();
                        self.setIoSessionState(.Idle);
                    } else {
                        self.channel_table.freeChannel(chan.local_id);
                        self.active_channel_id = null;
                        if (self.channel_table.activeCount() == 0) {
                            sshz.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
                        } else {
                            self.setIoSessionState(.ReadPktHdr);
                        }
                    }
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

fn writeServerChannelPacket(m: *SshzServer, channel: u32, data: []const u8) !void {
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

fn expectAndClearServerData(m: *SshzServer, channel: u32, data: []const u8) !void {
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

test "server window adjustment completion preserves concurrently received packet" {
    const limits = Sshz.ResourceLimits{
        .initial_channel_window = 12,
        .max_channel_window = 12,
        .channel_packet_size = 4,
        .max_peer_packet_size = 4,
    };
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.initWithLimits(
        prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
        limits,
    );
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(42, 12, 4).?;
    chan.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, Protocol.sizeof_PktHdr, .{ .ReadPktBody = m.iobuf_rd[0..Protocol.sizeof_PktHdr] });

    try writeServerChannelPacket(&m, chan.local_id, "aaaa");
    try expectAndClearServerData(&m, chan.local_id, "aaaa");
    try writeServerChannelPacket(&m, chan.local_id, "bbbb");
    try expectAndClearServerData(&m, chan.local_id, "bbbb");

    const adjust_len = m.wr_nbytes;
    try std.testing.expect(adjust_len > 1);
    var adjust = BufferReader.init(unencryptedPayload(try m.peek(adjust_len)));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST), try adjust.readU8());
    try std.testing.expectEqual(chan.remote_id, try adjust.readU32());
    try std.testing.expectEqual(@as(u32, 8), try adjust.readU32());
    try m.consumed(1);
    try writeServerChannelPacket(&m, chan.local_id, "cccc");
    try std.testing.expect(m.session.ioSessionState == .ReadPktCompletion);
    try m.consumed(adjust_len - 1);
    try expectAndClearServerData(&m, chan.local_id, "cccc");
    try std.testing.expectEqual(@as(u32, 8), chan.local_window);
}

fn parsePublicKeyBlobExact(blob: []const u8) Key.KeyError!Key.PublicKey {
    const public_key = try Key.parsePublicKeyBlob(blob);
    var canonical: Key.Blob = .{};
    const canonical_blob = try Key.writePublicKeyBlob(public_key, &canonical);
    if (!std.mem.eql(u8, canonical_blob, blob)) return error.InvalidKeyBlob;
    return public_key;
}

fn signatureAlgorithmExact(blob: []const u8) ?Key.SignatureAlgorithm {
    var reader = BufferReader.init(blob);
    const name = reader.readU32LenString() catch return null;
    _ = reader.readU32LenString() catch return null;
    if (reader.off != reader.payload.len) return null;
    return Key.SignatureAlgorithm.fromName(name);
}

fn buildUnencryptedPacket(buf: []u8, payload: []const u8) usize {
    const padding_length: u8 = 8;
    const packet_length: u32 = @intCast(payload.len + padding_length + 1);
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

fn consumeProducedChannelDataForTest(m: *SshzServer, destination: []u8, offset: usize) !usize {
    const packet = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA), try rdr.readU8());
    _ = try rdr.readU32();
    const data = try rdr.readU32LenString();
    @memcpy(destination[offset .. offset + data.len], data);
    try m.consumed(packet.len);
    return data.len;
}

fn writeKexInitPayloadForTest(writer: *BufferWriter) !void {
    try writeKexInitPayloadWithGuessForTest(
        writer,
        Protocol.kex_algorithms,
        Protocol.srv_hostkey_algo_name,
        false,
    );
}

fn writeKexInitPayloadWithGuessForTest(
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

test "server ignores exactly one packet after an incorrect KEX guess" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
    defer m.deinit();

    var kexinit_backing: [512]u8 = undefined;
    var kexinit = BufferWriter.init(&kexinit_backing, 0);
    try writeKexInitPayloadWithGuessForTest(
        &kexinit,
        "unsupported-kex,curve25519-sha256",
        "rsa-sha2-256,ssh-ed25519",
        true,
    );
    const kexinit_packet_len = buildUnencryptedPacket(&m.iobuf_rd, kexinit.active());
    m.session.kex_hash_order = .V_S;
    m.session.setSessionState(.KexInitRead);
    try m.session.handlePacket(m.iobuf_rd[0..kexinit_packet_len], &m);
    try std.testing.expect(m.session.ignore_next_kex_packet);

    const guessed_packet_len = buildUnencryptedPacket(
        &m.iobuf_rd,
        &.{@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT)},
    );
    m.session.setSessionState(.EcdhInitRead);
    try m.session.handlePacket(m.iobuf_rd[0..guessed_packet_len], &m);
    try std.testing.expect(!m.session.ignore_next_kex_packet);
    try std.testing.expectEqual(SessionState.EcdhInitRead, m.session.sessionState);
    try std.testing.expectError(
        BufferError.ReaderOutOfDataErr,
        m.session.handlePacket(m.iobuf_rd[0..guessed_packet_len], &m),
    );
}

fn handleAuthPayloadForTest(m: *SshzServer, payload: []const u8) !void {
    const packet_len = buildUnencryptedPacket(&m.iobuf_rd, payload);
    m.session.encrypted = false;
    m.session.setSessionState(.AuthRead);
    try m.session.handlePacket(m.iobuf_rd[0..packet_len], m);
}

fn writeUserAuthPrefixForTest(
    writer: *BufferWriter,
    username: []const u8,
    method: []const u8,
) !void {
    try writer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
    try writer.writeU32LenString(username);
    try writer.writeU32LenString("ssh-connection");
    try writer.writeU32LenString(method);
}

fn expectAuthFailurePayloadForTest(m: *SshzServer) !void {
    const packet = try m.peek(Protocol.MaxSSHPacket);
    var reader = BufferReader.init(unencryptedPayload(packet));
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE),
        try reader.readU8(),
    );
    try std.testing.expectEqualStrings(supported_auth_methods, try reader.readU32LenString());
    try std.testing.expect(!(try reader.readBoolean()));
    try std.testing.expectEqual(reader.payload.len, reader.off);
    try std.testing.expectEqual(SessionState.AuthRead, m.session.sessionState);
}

fn expectUnauthenticatedChannelOpenRejectedForTest(m: *SshzServer) !void {
    var payload_buffer: [128]u8 = undefined;
    var payload = BufferWriter.init(&payload_buffer, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try payload.writeU32LenString("session");
    try payload.writeU32(7);
    try payload.writeU32(1024);
    try payload.writeU32(256);

    const packet_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        m.session.handlePacket(m.iobuf_rd[0..packet_len], m),
    );
    try std.testing.expect(!m.session.isActive());
    try std.testing.expectEqual(SessionState.AuthRead, m.session.sessionState);
    try std.testing.expectEqual(@as(?u32, null), m.session.active_channel_id);
    for (m.session.channel_table.channels) |channel| {
        try std.testing.expect(channel == null);
    }
}

fn advanceImmediateAuthDenialForTest(m: *SshzServer) !void {
    try std.testing.expectEqual(SessionState.UserAuthDenied, m.session.sessionState);
    try m.advance();
    try expectAuthFailurePayloadForTest(m);
}

fn rejectAuthEventForTest(
    m: *SshzServer,
    expected_username: []const u8,
    expected_method: Sshz.AuthMethod,
) !void {
    const event = try m.getNextEvent();
    const event_code = switch (event) {
        .Event => |code| code,
        else => return error.TestUnexpectedResult,
    };
    switch (event_code) {
        .UserAuth => |credentials| {
            try std.testing.expectEqualStrings(expected_username, credentials.username);
            try std.testing.expectEqual(expected_method, credentials.method());
        },
        else => return error.TestUnexpectedResult,
    }
    try m.decideUserAuth(.Deny);
    for (m.iobuf_rd) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (m.iobuf_decompressed) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try expectAuthFailurePayloadForTest(m);
    try expectUnauthenticatedChannelOpenRejectedForTest(m);
}

test "server authentication denials have one packet and state shape" {
    const password_cases = [_]struct {
        username: []const u8,
        password: []const u8,
    }{
        .{ .username = "invalid-user", .password = "correct-password" },
        .{ .username = "valid-user", .password = "invalid-password" },
    };

    for (password_cases) |case| {
        var prng = std.Random.DefaultPrng.init(42);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var payload_buffer: [256]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, case.username, "password");
        try payload.writeBoolean(false);
        try payload.writeU32LenString(case.password);

        try handleAuthPayloadForTest(&m, payload.active());
        try std.testing.expectEqual(SessionState.CheckUserPasswordAuth, m.session.sessionState);
        try rejectAuthEventForTest(&m, case.username, .Password);
    }

    {
        var prng = std.Random.DefaultPrng.init(43);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var payload_buffer: [256]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "valid-user", "password");
        try payload.writeBoolean(true);
        try payload.writeU32LenString("old-password");
        try payload.writeU32LenString("new-password");

        try handleAuthPayloadForTest(&m, payload.active());
        try advanceImmediateAuthDenialForTest(&m);
    }

    {
        var prng = std.Random.DefaultPrng.init(44);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var payload_buffer: [256]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "valid-user", "unsupported-method");

        try handleAuthPayloadForTest(&m, payload.active());
        try advanceImmediateAuthDenialForTest(&m);
    }
}

test "server none and unsupported keyboard-interactive cannot authenticate or open channels" {
    {
        var prng = std.Random.DefaultPrng.init(51);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var payload_buffer: [128]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "none-user", "none");
        try handleAuthPayloadForTest(&m, payload.active());

        const event = try m.getNextEvent();
        const event_code = switch (event) {
            .Event => |code| code,
            else => return error.TestUnexpectedResult,
        };
        switch (event_code) {
            .UserAuth => |credentials| {
                try std.testing.expectEqualStrings("none-user", credentials.username);
                try std.testing.expectEqual(Sshz.AuthMethod.None, credentials.method());
            },
            else => return error.TestUnexpectedResult,
        }

        // Clearing without a decision must default to denial.
        try m.clearEvent(event_code);
        try expectAuthFailurePayloadForTest(&m);
        try expectUnauthenticatedChannelOpenRejectedForTest(&m);
    }

    {
        var prng = std.Random.DefaultPrng.init(52);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var payload_buffer: [192]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "keyboard-user", "keyboard-interactive");
        try payload.writeU32LenString("");
        try payload.writeU32LenString("otp");
        try handleAuthPayloadForTest(&m, payload.active());

        try std.testing.expectEqual(SessionState.UserAuthDenied, m.session.sessionState);
        try std.testing.expectEqual(@as(?PendingAuthorizationKind, null), m.session.pending_authorization);
        try m.advance();
        try expectAuthFailurePayloadForTest(&m);
        try expectUnauthenticatedChannelOpenRejectedForTest(&m);
    }

    {
        var prng = std.Random.DefaultPrng.init(53);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var payload_buffer: [192]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "keyboard-user", "keyboard-interactive");
        try payload.writeU32LenString("");

        const packet_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());
        m.session.encrypted = false;
        m.session.setSessionState(.AuthRead);
        try std.testing.expectError(
            BufferError.ReaderOutOfDataErr,
            m.session.handlePacket(m.iobuf_rd[0..packet_len], &m),
        );
        try std.testing.expect(!m.session.user_authenticated);
        try std.testing.expectEqual(@as(?PendingAuthorizationKind, null), m.session.pending_authorization);
    }
}

test "server terminal cleanup is idempotent and clears host and exchange keys" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(
        prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
    );

    @memset(&session.shared_secret_k, 0xA5);
    @memset(&session.session_id, 0x5A);
    @memset(std.mem.asBytes(&session.ecdh_ephem_keypair), 0xCC);
    session.ecdh_ephem_keypair_active = true;
    session.failClosed();
    session.failClosed();

    try std.testing.expect(!session.host_private_key_active);
    try std.testing.expect(!session.ecdh_ephem_keypair_active);
    try std.testing.expect(!session.kex_hasher.active);
    for (session.shared_secret_k) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (session.session_id) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (std.mem.asBytes(&session.ecdh_ephem_keypair)) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }

    session.deinit();
    session.deinit();
}

test "server public-key probe and denial state machine preserves RFC shapes" {
    var probe_prng = std.Random.DefaultPrng.init(45);
    var probe = try SshzServer.init(
        probe_prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
    );
    defer probe.deinit();

    var public_key_storage: Key.Blob = .{};
    const public_key = try probe.session.host_private_key.publicBlob(&public_key_storage);

    var probe_payload_buffer: [256]u8 = undefined;
    var probe_payload = BufferWriter.init(&probe_payload_buffer, 0);
    try writeUserAuthPrefixForTest(&probe_payload, "any-user", "publickey");
    try probe_payload.writeBoolean(false);
    try probe_payload.writeU32LenString("ssh-ed25519");
    try probe_payload.writeU32LenString(public_key);
    try handleAuthPayloadForTest(&probe, probe_payload.active());

    try std.testing.expectEqual(SessionState.CheckUserPasswordAuth, probe.session.sessionState);
    const probe_event = try probe.getNextEvent();
    switch (probe_event) {
        .Event => |code| switch (code) {
            .UserAuth => |credentials| {
                try std.testing.expectEqualStrings("any-user", credentials.username);
                try std.testing.expectEqual(Sshz.AuthMethod.PublicKey, credentials.method());
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try probe.decideUserAuth(.Allow);
    const probe_packet = try probe.peek(Protocol.MaxSSHPacket);
    var probe_reader = BufferReader.init(unencryptedPayload(probe_packet));
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK),
        try probe_reader.readU8(),
    );
    try std.testing.expectEqualStrings("ssh-ed25519", try probe_reader.readU32LenString());
    try std.testing.expectEqualSlices(u8, public_key, try probe_reader.readU32LenString());
    try std.testing.expectEqual(probe_reader.payload.len, probe_reader.off);
    try std.testing.expectEqual(SessionState.AuthRead, probe.session.sessionState);
    try expectUnauthenticatedChannelOpenRejectedForTest(&probe);

    {
        var prng = std.Random.DefaultPrng.init(53);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var key_storage: Key.Blob = .{};
        const key = try m.session.host_private_key.publicBlob(&key_storage);
        var payload_buffer: [256]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "unauthorized-probe", "publickey");
        try payload.writeBoolean(false);
        try payload.writeU32LenString("ssh-ed25519");
        try payload.writeU32LenString(key);

        try handleAuthPayloadForTest(&m, payload.active());
        try std.testing.expectEqual(SessionState.CheckUserPasswordAuth, m.session.sessionState);
        try rejectAuthEventForTest(&m, "unauthorized-probe", .PublicKey);
    }

    {
        var prng = std.Random.DefaultPrng.init(46);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var payload_buffer: [256]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "any-user", "publickey");
        try payload.writeBoolean(false);
        try payload.writeU32LenString("ssh-ed25519");
        try payload.writeU32LenString("\x00\x00\x00\x0bssh-ed25519");

        try handleAuthPayloadForTest(&m, payload.active());
        try advanceImmediateAuthDenialForTest(&m);
    }

    {
        var prng = std.Random.DefaultPrng.init(47);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var key_storage: Key.Blob = .{};
        const key = try m.session.host_private_key.publicBlob(&key_storage);
        var typed_signature_buffer: [128]u8 = undefined;
        var typed_signature = BufferWriter.init(&typed_signature_buffer, 0);
        try typed_signature.writeU32LenString("ssh-ed25519");
        try typed_signature.writeU32LenString(&(.{0} ** 64));

        var payload_buffer: [512]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "any-user", "publickey");
        try payload.writeBoolean(true);
        try payload.writeU32LenString("ssh-ed25519");
        try payload.writeU32LenString(key);
        try payload.writeU32LenString(typed_signature.active());

        try handleAuthPayloadForTest(&m, payload.active());
        try advanceImmediateAuthDenialForTest(&m);
    }

    {
        var prng = std.Random.DefaultPrng.init(48);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        var key_storage: Key.Blob = .{};
        const key = try m.session.host_private_key.publicBlob(&key_storage);
        var malformed_signature_buffer: [32]u8 = undefined;
        var malformed_signature = BufferWriter.init(&malformed_signature_buffer, 0);
        try malformed_signature.writeU32LenString("ssh-ed25519");

        var payload_buffer: [512]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "any-user", "publickey");
        try payload.writeBoolean(true);
        try payload.writeU32LenString("ssh-ed25519");
        try payload.writeU32LenString(key);
        try payload.writeU32LenString(malformed_signature.active());

        try handleAuthPayloadForTest(&m, payload.active());
        try advanceImmediateAuthDenialForTest(&m);
    }

    {
        var prng = std.Random.DefaultPrng.init(49);
        var m = try SshzServer.init(
            prng.random(),
            @import("privkey.zig").testkey_valid,
            std.testing.allocator,
        );
        defer m.deinit();

        m.session.session_id = .{0x5a} ** Protocol.hash_algo.digest_length;
        var key_storage: Key.Blob = .{};
        const key = try m.session.host_private_key.publicBlob(&key_storage);

        var signed_data_buffer: [512]u8 = undefined;
        var signed_data = BufferWriter.init(&signed_data_buffer, 0);
        try signed_data.writeU32LenString(&m.session.session_id);
        try writeUserAuthPrefixForTest(&signed_data, "unauthorized-user", "publickey");
        try signed_data.writeBoolean(true);
        try signed_data.writeU32LenString("ssh-ed25519");
        try signed_data.writeU32LenString(key);

        var signature_storage: Key.SignatureBlob = .{};
        const signature = try m.session.host_private_key.sign(
            .Ed25519,
            signed_data.active(),
            &signature_storage,
        );

        var payload_buffer: [768]u8 = undefined;
        var payload = BufferWriter.init(&payload_buffer, 0);
        try writeUserAuthPrefixForTest(&payload, "unauthorized-user", "publickey");
        try payload.writeBoolean(true);
        try payload.writeU32LenString("ssh-ed25519");
        try payload.writeU32LenString(key);
        try payload.writeU32LenString(signature);

        try handleAuthPayloadForTest(&m, payload.active());
        try std.testing.expectEqual(SessionState.CheckUserPasswordAuth, m.session.sessionState);
        try rejectAuthEventForTest(&m, "unauthorized-user", .PublicKey);
    }
}

test "server malformed authentication packet remains a parser error" {
    var prng = std.Random.DefaultPrng.init(50);
    var m = try SshzServer.init(
        prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
    );
    defer m.deinit();

    var payload_buffer: [128]u8 = undefined;
    var payload = BufferWriter.init(&payload_buffer, 0);
    try writeUserAuthPrefixForTest(&payload, "user", "password");
    try payload.writeBoolean(false);

    try std.testing.expectError(
        BufferError.ReaderOutOfDataErr,
        handleAuthPayloadForTest(&m, payload.active()),
    );
    try std.testing.expectEqual(SessionState.AuthRead, m.session.sessionState);
}

test "server rekey hashes retained exact client and server versions" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
    defer session.deinit();

    try session.setPeerProtocolVersion("SSH-2.0-exact_client comment");
    session.clearAndFreeOptional(&session.server_version);
    session.server_version = try std.testing.allocator.dupe(u8, "SSH-2.0-exact_server comment");
    session.resetKexHasherForRekey();

    var expected_hasher = Hasher(Protocol.hash_algo).init();
    expected_hasher.writeU32LenString("SSH-2.0-exact_client comment");
    expected_hasher.writeU32LenString("SSH-2.0-exact_server comment");
    var expected: [Protocol.hash_algo.digest_length]u8 = undefined;
    expected_hasher.final(&expected, null);
    var actual: [Protocol.hash_algo.digest_length]u8 = undefined;
    session.kex_hasher.final(&actual, null);

    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "server rekey preserves initial session id for key derivation" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
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

test "simultaneous server local and client rekey preserves exact local KEXINIT" {
    var prng = std.Random.DefaultPrng.init(142);
    var m = try SshzServer.init(
        prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
    );
    defer m.deinit();
    try m.session.setPeerProtocolVersion("SSH-2.0-test_client");
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
    try std.testing.expectEqualStrings(local_payload, m.session.pending_server_kexinit.?);
    try std.testing.expectEqual(SessionState.KexInitRead, m.session.sessionState);
    try m.consumed(local_packet.len);

    var peer_payload_buf: [512]u8 = undefined;
    var peer_payload = BufferWriter.init(&peer_payload_buf, 0);
    try writeKexInitPayloadForTest(&peer_payload);
    const peer_packet_len = buildUnencryptedPacket(&m.iobuf_rd, peer_payload.active());
    try m.session.handlePacket(m.iobuf_rd[0..peer_packet_len], &m);

    try std.testing.expect(m.session.is_rekeying);
    try std.testing.expectEqual(SessionState.EcdhInitRead, m.session.sessionState);
    try std.testing.expect(m.session.pending_server_kexinit == null);
    try std.testing.expectEqual(Protocol.KexHashOrder.I_S, m.session.kex_hash_order);

    var expected_hasher = Hasher(Protocol.hash_algo).init();
    expected_hasher.writeU32LenString(m.session.client_version.?);
    expected_hasher.writeU32LenString(m.session.server_version.?);
    expected_hasher.writeU32LenString(peer_payload.active());
    expected_hasher.writeU32LenString(local_payload_copy[0..local_payload_len]);
    var expected: [Protocol.hash_algo.digest_length]u8 = undefined;
    expected_hasher.final(&expected, null);
    var actual: [Protocol.hash_algo.digest_length]u8 = undefined;
    m.session.kex_hasher.final(&actual, null);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "server rekey activates outbound and inbound keys at NEWKEYS boundaries" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
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
    defer old_c2s.clear();
    var old_s2c = m.session.keydata.s2c;
    const new_c2s_key = m.session.pending_c2s_keys.?.key;
    const new_s2c_key = m.session.pending_s2c_keys.?.key;

    m.session.setSessionState(.NewKeysWrite);
    try m.session.advanceSession(&m);
    const server_newkeys = try m.peek(Protocol.MaxSSHPacket);
    try std.testing.expectEqualSlices(u8, &new_s2c_key, &m.session.keydata.s2c.key);
    try std.testing.expectEqual(@as(u32, 1), m.session.keydata.s2c.seq);
    try std.testing.expectEqual(@as(u64, 5), m.session.keydata.s2c.epoch);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.s2c.encrypted_bytes);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.s2c.encrypted_packets);
    try std.testing.expectEqual(@as(?u64, 100), m.session.keydata.s2c.activated_at_monotonic_tick);
    try std.testing.expectEqual(@as(u64, 3), m.session.keydata.c2s.epoch);
    try std.testing.expectEqual(@as(u64, 7), m.session.keydata.c2s.encrypted_packets);
    try std.testing.expectEqualSlices(u8, &old_c2s.key, &m.session.keydata.c2s.key);
    try std.testing.expect(m.session.pending_s2c_keys == null);
    try std.testing.expect(m.session.pending_c2s_keys != null);

    var verifier_prng = std.Random.DefaultPrng.init(7);
    var verifier = try Sshz.SshzClient.init(verifier_prng.random(), "testuser", std.testing.allocator);
    defer verifier.deinit();
    verifier.session.keydata.s2c.clear();
    verifier.session.keydata.s2c = old_s2c;
    old_s2c = .{ .seq = 0 };
    verifier.session.inbound_encrypted = true;
    @memcpy(verifier.iobuf_rd[0..server_newkeys.len], server_newkeys);
    try decryptFirstBlockForTest(verifier.iobuf_rd[0..server_newkeys.len], &verifier.session.keydata.s2c);
    var server_rdr = try verifier.getRecvBuffer(
        verifier.iobuf_rd[0..server_newkeys.len],
        &verifier.session.keydata.s2c,
    );
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS), try server_rdr.readU8());

    var client_packet_buf: [Protocol.MaxSSHPacket]u8 = undefined;
    var client_packet = BufferWriter.init(&client_packet_buf, Protocol.sizeof_PktHdr);
    try client_packet.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
    var client_prng = std.Random.DefaultPrng.init(99);
    var client_rand = client_prng.random();
    const wrapped_client_newkeys = try Protocol.wrapPkt(
        &client_rand,
        true,
        &old_c2s,
        &client_packet,
        &client_packet_buf,
    );
    @memcpy(m.iobuf_rd[0..wrapped_client_newkeys.len], wrapped_client_newkeys);
    try decryptFirstBlockForTest(m.iobuf_rd[0..wrapped_client_newkeys.len], &m.session.keydata.c2s);
    m.session.setSessionState(.NewKeysRead);
    try m.session.handlePacket(m.iobuf_rd[0..wrapped_client_newkeys.len], &m);

    try std.testing.expectEqualSlices(u8, &new_c2s_key, &m.session.keydata.c2s.key);
    try std.testing.expectEqual(@as(u32, 1), m.session.keydata.c2s.seq);
    try std.testing.expectEqual(@as(u64, 4), m.session.keydata.c2s.epoch);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.c2s.encrypted_bytes);
    try std.testing.expectEqual(@as(u64, 0), m.session.keydata.c2s.encrypted_packets);
    try std.testing.expectEqual(@as(?u64, 100), m.session.keydata.c2s.activated_at_monotonic_tick);
    try std.testing.expect(m.session.pending_c2s_keys == null);
}

test "server rekey gates deferred channel traffic until NEWKEYS completes" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
    defer m.deinit();
    try m.session.setPeerProtocolVersion("SSH-2.0-test_client");

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

    var client_payload_buf: [512]u8 = undefined;
    var client_payload = BufferWriter.init(&client_payload_buf, 0);
    try writeKexInitPayloadForTest(&client_payload);
    const client_packet_len = buildUnencryptedPacket(&m.iobuf_rd, client_payload.active());
    m.iostate_rd = .Idle;
    m.session.setIoSessionState(.{ .ReadPktCompletion = m.iobuf_rd[0..client_packet_len] });

    var first_fragment: [1000]u8 = undefined;
    _ = try consumeProducedChannelDataForTest(&m, &first_fragment, 0);
    try std.testing.expect(m.session.is_rekeying);
    try std.testing.expectEqual(@as(usize, 1000), channel_a.write_buf_nbytes);
    try std.testing.expect(channel_b.eof_pending);

    const server_kexinit = try m.peek(Protocol.MaxSSHPacket);
    try std.testing.expectEqual(
        @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT),
        unencryptedPayload(server_kexinit)[0],
    );
    try m.consumed(server_kexinit.len);

    m.iostate_rd = .Idle;
    m.session.session_id = .{0x11} ** Protocol.hash_algo.digest_length;
    m.session.shared_secret_k = .{0x22} ** Protocol.kex_algo.shared_length;
    m.session.negotiated_compression_c2s = .None;
    m.session.negotiated_compression_s2c = .None;
    try m.session.installExchangeKeys(.{0x33} ** Protocol.hash_algo.digest_length);
    const new_s2c_key = m.session.pending_s2c_keys.?.key;
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
    try std.testing.expectEqual(SessionState.NewKeysRead, m.session.sessionState);
    try std.testing.expectEqual(@as(usize, 0), channel_a.tx_in_flight_len);

    try m.session.activatePendingC2sKeys(&m);
    m.session.is_rekeying = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    m.session.setIoSessionState(.Idle);
    m.iostate_rd = .Idle;
    try m.advance();
    try m.advance();

    try std.testing.expectEqualSlices(u8, &new_s2c_key, &m.session.keydata.s2c.key);
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

test "server channel write retains suffix across peer packet limit" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(77, 2500, 1000).?;
    chan.state = .DataRx;
    const total_len: usize = 2500;
    for (chan.write_buf[0..total_len], 0..) |*byte, index| byte.* = @truncate(index);
    try m.session.channelWriteComplete(chan.local_id, total_len);
    try m.advance();
    try m.advance();
    try std.testing.expectEqual(ChannelState.DataRx, chan.state);
    try std.testing.expectEqual(@as(usize, total_len), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(usize, 1000), chan.tx_in_flight_len);
    try std.testing.expectEqual(@as(usize, 0), (try m.getChannelWriteBuffer(chan.local_id)).len);
    try std.testing.expectError(IoError.cannotAcceptWrite, m.channelWriteComplete(chan.local_id, 1));
    try std.testing.expect(!(try m.channelEofFlushed(chan.local_id)));
    try m.sendChannelEof(chan.local_id);
    try std.testing.expect(chan.eof_pending);
    try std.testing.expect(!(try m.channelEofFlushed(chan.local_id)));

    var received: [total_len]u8 = undefined;
    var received_len: usize = 0;
    received_len += try consumeProducedChannelDataForTest(&m, &received, received_len);
    try std.testing.expectEqual(@as(usize, 1500), chan.write_buf_nbytes);
    received_len += try consumeProducedChannelDataForTest(&m, &received, received_len);
    try std.testing.expectEqual(@as(usize, 500), chan.write_buf_nbytes);
    received_len += try consumeProducedChannelDataForTest(&m, &received, received_len);

    try std.testing.expectEqual(total_len, received_len);
    try std.testing.expectEqual(@as(usize, 0), chan.write_buf_nbytes);
    try std.testing.expectEqual(@as(u32, 0), chan.peer_window);
    for (received, 0..) |byte, index| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);

    const eof_packet = try m.peek(Protocol.MaxSSHPacket);
    var eof_reader = BufferReader.init(unencryptedPayload(eof_packet));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF), try eof_reader.readU8());
    try std.testing.expect(!(try m.channelEofFlushed(chan.local_id)));
    try m.consumed(eof_packet.len);
    try std.testing.expect(try m.channelEofFlushed(chan.local_id));
    try std.testing.expect(chan.eof_sent);
    try std.testing.expect(chan.control_in_flight == null);
    try std.testing.expectEqual(@as(usize, 0), chan.tx_in_flight_len);
}

test "server local close discards window-blocked suffix after in-flight fragment" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
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

test "server completion schedules pending control on another channel" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
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

test "server close completion dispatches next channel control during active read" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
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

test "server runtime channel buffer pending and peer limits enforce boundaries" {
    const limits = Sshz.ResourceLimits{
        .initial_channel_window = 100,
        .max_channel_window = 100,
        .channel_packet_size = 50,
        .max_peer_packet_size = 50,
        .max_channel_buffered_data = 8,
        .max_pending_buffered_data = 12,
    };
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.initWithLimits(
        prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
        limits,
    );
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

test "server rejects channel data above packet and receive window limits" {
    const limits = Sshz.ResourceLimits{
        .initial_channel_window = 8,
        .max_channel_window = 8,
        .channel_packet_size = 4,
        .max_peer_packet_size = 4,
        .max_channel_buffered_data = 4,
        .max_pending_buffered_data = 4,
    };
    var prng = std.Random.DefaultPrng.init(42);

    var packet_server = try SshzServer.initWithLimits(
        prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
        limits,
    );
    defer packet_server.deinit();
    const packet_chan = packet_server.session.channel_table.allocChannel(42, 8, 4).?;
    packet_chan.state = .DataRx;
    packet_server.session.user_authenticated = true;
    var payload_backing: [64]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(packet_chan.local_id);
    try payload.writeU32LenString("12345");
    const packet_len = buildUnencryptedPacket(&packet_server.iobuf_rd, payload.active());
    try std.testing.expectError(
        error.ChannelPacketTooLarge,
        packet_server.session.handlePacket(packet_server.iobuf_rd[0..packet_len], &packet_server),
    );
    try std.testing.expectEqual(@as(u32, 8), packet_chan.local_window);

    var window_server = try SshzServer.initWithLimits(
        prng.random(),
        @import("privkey.zig").testkey_valid,
        std.testing.allocator,
        limits,
    );
    defer window_server.deinit();
    const window_chan = window_server.session.channel_table.allocChannel(42, 8, 4).?;
    window_chan.state = .DataRx;
    window_server.session.user_authenticated = true;
    window_chan.local_window = 3;
    payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(window_chan.local_id);
    try payload.writeU32LenString("1234");
    const window_len = buildUnencryptedPacket(&window_server.iobuf_rd, payload.active());
    try std.testing.expectError(
        error.ReceiveWindowExceeded,
        window_server.session.handlePacket(window_server.iobuf_rd[0..window_len], &window_server),
    );
    try std.testing.expectEqual(@as(u32, 3), window_chan.local_window);
}

test "handlePacket: channel data is accepted while a rekey is in flight" {
    // Regression: RFC 4253 s9 allows connection-protocol packets that the peer
    // sent before it saw our KEXINIT to arrive during a rekey. Gating on
    // sessionState would drop them; the authentication latch must not.
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
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
            .RxData => |data| try std.testing.expectEqualSlices(u8, "hello", data.data),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    // The in-flight packet must not clobber the parked key-exchange state,
    // or the peer's KEXINIT would later be misread as peer-initiated.
    try std.testing.expectEqual(SessionState.KexInitRead, m.session.sessionState);
    try std.testing.expectEqual(SessionState.ChannelActive, m.session.rekey_resume_state.?);
}

test "handlePacket: direct-tcpip open emits request and accept confirms" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();
    m.session.user_authenticated = true;
    m.session.setSessionState(.Authenticated);

    var payload_backing: [160]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString("direct-tcpip");
    try pw.writeU32(77); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size
    try pw.writeU32LenString("example.com");
    try pw.writeU32(443);
    try pw.writeU32LenString("127.0.0.1");
    try pw.writeU32(55555);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    const channel_id = switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpenRequest => |request| blk: {
                switch (request.request) {
                    .DirectTcpip => |tcp| {
                        try std.testing.expectEqualStrings("example.com", tcp.host);
                        try std.testing.expectEqual(@as(u32, 443), tcp.port);
                        try std.testing.expectEqualStrings("127.0.0.1", tcp.originator_host);
                        try std.testing.expectEqual(@as(u32, 55555), tcp.originator_port);
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
    try std.testing.expectEqual(ChannelType.DirectTcpip, chan.channel_type);
    try std.testing.expectEqual(ChannelState.Open, chan.state);

    try m.acceptChannelOpen(channel_id);
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION), try rdr.readU8());
    try std.testing.expectEqual(@as(u32, 77), try rdr.readU32());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
}

test "handlePacket: session open requires an application decision" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();
    m.session.user_authenticated = true;
    m.session.setSessionState(.Authenticated);

    var payload_backing: [96]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString("session");
    try pw.writeU32(78);
    try pw.writeU32(32768);
    try pw.writeU32(4096);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    const event_code = switch (evt) {
        .Event => |code| code,
        else => return error.TestUnexpectedResult,
    };
    const channel_id = switch (event_code) {
        .ChannelOpenRequest => |request| blk: {
            switch (request.request) {
                .Session => {},
                else => return error.TestUnexpectedResult,
            }
            break :blk request.channel;
        },
        else => return error.TestUnexpectedResult,
    };
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ChannelType.Session, chan.channel_type);
    try std.testing.expectEqual(ChannelState.Open, chan.state);
    try std.testing.expectError(IoError.badClearEvent, m.clearEvent(event_code));
    try std.testing.expectEqual(ChannelState.Open, chan.state);

    try m.acceptChannelOpen(channel_id);
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION), try rdr.readU8());
    try std.testing.expectEqual(@as(u32, 78), try rdr.readU32());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
}

test "rejectChannelOpen writes caller-provided failure" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();
    m.session.user_authenticated = true;
    m.session.setSessionState(.Authenticated);

    var payload_backing: [160]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString("direct-tcpip");
    try pw.writeU32(88); // sender channel
    try pw.writeU32(32768);
    try pw.writeU32(4096);
    try pw.writeU32LenString("example.com");
    try pw.writeU32(443);
    try pw.writeU32LenString("127.0.0.1");
    try pw.writeU32(55555);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    const channel_id = switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpenRequest => |request| request.channel,
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };

    try m.rejectChannelOpen(channel_id, SshOpenFailureReason.ConnectFailed, "connect failed");
    try std.testing.expect(m.session.channel_table.findByLocalId(channel_id) == null);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE), try rdr.readU8());
    try std.testing.expectEqual(@as(u32, 88), try rdr.readU32());
    try std.testing.expectEqual(SshOpenFailureReason.ConnectFailed, try rdr.readU32());
    try std.testing.expectEqualStrings("connect failed", try rdr.readU32LenString());
}

test "handlePacket: unknown channel type writes open failure" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();
    m.session.user_authenticated = true;
    m.session.setSessionState(.Authenticated);

    var payload_backing: [64]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString("x11");
    try pw.writeU32(99); // sender channel
    try pw.writeU32(32768);
    try pw.writeU32(4096);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE), try rdr.readU8());
    try std.testing.expectEqual(@as(u32, 99), try rdr.readU32());
    try std.testing.expectEqual(SshOpenFailureReason.UnknownChannelType, try rdr.readU32());
    try std.testing.expectEqualStrings("unknown channel type", try rdr.readU32LenString());
}

test "handlePacket: global requests are rejected before authentication" {
    // Regression: an unauthenticated peer must not reach global-request
    // handling, which would otherwise ask the application to bind a
    // listening socket on its behalf.
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    var payload_backing: [96]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST));
    try pw.writeU32LenString("tcpip-forward");
    try pw.writeBoolean(true);
    try pw.writeU32LenString("127.0.0.1");
    try pw.writeU32(0);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    // sessionState is still .Init: no kex and no userauth.
    try std.testing.expectError(
        error.UnexpectedResponse,
        m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m),
    );
    try std.testing.expect(m.session.pending_global_request == null);
}

test "handlePacket: server rejects a KEXINIT that arrives mid initial handshake" {
    // Regression: a second KEXINIT before the first exchange completes must not
    // be classified as a peer-initiated rekey, which would leave session_id
    // all-zero while it still binds publickey userauth signatures.
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();
    try m.session.setPeerProtocolVersion("SSH-2.0-test_client");

    var payload_buf: [512]u8 = undefined;
    var payload = BufferWriter.init(&payload_buf, 0);
    try writeKexInitPayloadForTest(&payload);
    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, payload.active());

    // Server is awaiting KEX_ECDH_INIT, i.e. the first exchange is incomplete.
    m.session.setSessionState(.EcdhInitRead);
    m.session.setIoSessionState(.ReadPktHdr);

    try std.testing.expectError(
        error.UnexpectedResponse,
        m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m),
    );
    try std.testing.expect(!m.session.is_rekeying);
    try std.testing.expect(!m.session.session_id_established);
}

test "handlePacket: tcpip-forward emits event and accept writes allocated port" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    var payload_backing: [96]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST));
    try pw.writeU32LenString("tcpip-forward");
    try pw.writeBoolean(true);
    try pw.writeU32LenString("127.0.0.1");
    try pw.writeU32(0);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    @memset(&m.iobuf_rd, 0xaa);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .TcpipForward => |forward| {
                try std.testing.expectEqualStrings("127.0.0.1", forward.bind_address);
                try std.testing.expectEqual(@as(u32, 0), forward.bind_port);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try m.acceptTcpipForward(2222);
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS), try rdr.readU8());
    try std.testing.expectEqual(@as(u32, 2222), try rdr.readU32());
}

test "handlePacket: cancel-tcpip-forward emits event and reject writes failure" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    var payload_backing: [96]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST));
    try pw.writeU32LenString("cancel-tcpip-forward");
    try pw.writeBoolean(true);
    try pw.writeU32LenString("127.0.0.1");
    try pw.writeU32(2200);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .CancelTcpipForward => |cancel| {
                try std.testing.expectEqualStrings("127.0.0.1", cancel.bind_address);
                try std.testing.expectEqual(@as(u32, 2200), cancel.bind_port);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try m.rejectCancelTcpipForward();
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE), try rdr.readU8());
}

test "handlePacket: unknown global request with reply writes failure" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    var payload_backing: [64]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST));
    try pw.writeU32LenString("unknown-request");
    try pw.writeBoolean(true);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE), try rdr.readU8());
}

test "openForwardedTcpipChannel writes forwarded-tcpip open payload" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.user_authenticated = true;
    m.session.setSessionState(.Authenticated);

    const channel_id = try m.openForwardedTcpipChannel("127.0.0.1", 2200, "203.0.113.10", 44444);
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ChannelType.ForwardedTcpip, chan.channel_type);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try rdr.readU8());
    try std.testing.expectEqualStrings("forwarded-tcpip", try rdr.readU32LenString());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
    try std.testing.expectEqual(Sshz.default_channel_window, try rdr.readU32());
    try std.testing.expectEqual(Protocol.MaxChannelDataLen, try rdr.readU32());
    try std.testing.expectEqualStrings("127.0.0.1", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 2200), try rdr.readU32());
    try std.testing.expectEqualStrings("203.0.113.10", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 44444), try rdr.readU32());
}

test "unconfirmed server channel defers close until remote id is known" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), @import("privkey.zig").testkey_valid, std.testing.allocator);
    defer m.deinit();

    const existing = m.session.channel_table.allocChannel(0, 1000, 1000).?;
    existing.state = .DataRx;
    m.session.user_authenticated = true;
    m.session.setSessionState(.ChannelActive);
    const channel_id = try m.openForwardedTcpipChannel("127.0.0.1", 2200, "203.0.113.10", 44444);
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
    try confirmation.writeU32(88);
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
    try std.testing.expectEqual(@as(u32, 88), try close_reader.readU32());
    try std.testing.expect(pending.remote_id_known);
}

test "handlePacket: auth-agent request surfaces channel request event" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.Session, 100, 32768, 32768).?;
    chan.state = .DataRx;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
    try pw.writeU32(chan.local_id);
    try pw.writeU32LenString(Protocol.channel_request_auth_agent);
    try pw.writeBoolean(false);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.user_authenticated = true;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelRequest => |request| {
                try std.testing.expectEqual(chan.local_id, request.channel);
                switch (request.request) {
                    .AgentForward => {},
                    else => return error.TestUnexpectedResult,
                }
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: session requests on non-session channels fail before events" {
    const request_names = [_][]const u8{
        "pty-req",
        "x11-req",
        "shell",
        "exec",
        "subsystem",
        "env",
        "window-change",
        "xon-xoff",
        "signal",
        "exit-status",
        "exit-signal",
        "break",
        Protocol.channel_request_auth_agent,
    };

    for (request_names, 0..) |request_name, index| {
        const privkey = @import("privkey.zig");
        var prng = std.Random.DefaultPrng.init(@intCast(100 + index));
        var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
        defer m.deinit();

        const chan = m.session.channel_table.allocChannelKind(.Session, 100, 32768, 32768).?;
        chan.channel_type = if (index % 2 == 0) .DirectTcpip else .ForwardedTcpip;
        chan.state = .DataRx;

        var payload_backing: [192]u8 = undefined;
        var pw = BufferWriter.init(&payload_backing, 0);
        try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
        try pw.writeU32(chan.local_id);
        try pw.writeU32LenString(request_name);
        try pw.writeBoolean(true);
        if (std.mem.eql(u8, request_name, "pty-req")) {
            try pw.writeU32LenString("xterm");
            try pw.writeU32(80);
            try pw.writeU32(24);
            try pw.writeU32(0);
            try pw.writeU32(0);
        } else if (std.mem.eql(u8, request_name, "exec")) {
            try pw.writeU32LenString("id");
        } else if (std.mem.eql(u8, request_name, "subsystem")) {
            try pw.writeU32LenString("sftp");
        } else if (std.mem.eql(u8, request_name, "env")) {
            try pw.writeU32LenString("LANG");
            try pw.writeU32LenString("C");
        } else if (std.mem.eql(u8, request_name, "window-change")) {
            try pw.writeU32(100);
            try pw.writeU32(40);
            try pw.writeU32(0);
            try pw.writeU32(0);
        } else if (std.mem.eql(u8, request_name, "signal")) {
            try pw.writeU32LenString("TERM");
        }

        const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
        m.session.encrypted = false;
        m.session.user_authenticated = true;
        try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
        try m.advance();

        const packet = try m.peek(Protocol.MaxSSHPacket);
        var rdr = BufferReader.init(unencryptedPayload(packet));
        try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_FAILURE), try rdr.readU8());
        try std.testing.expectEqual(@as(u32, 100), try rdr.readU32());
        try std.testing.expectEqual(rdr.payload.len, rdr.off);
    }
}

test "openAgentChannel sends an agent channel open" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const channel_id = try m.openAgentChannel();
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(.AgentForward, chan.kind);
    try std.testing.expectEqual(ChannelState.OpenSent, chan.state);
    try std.testing.expect(m.iostate_wr != .Idle);
}

test "handlePacket: agent channel open confirmation activates server channel" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const channel_id = try m.session.openAgentChannel();
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    chan.state = .OpenSent;
    m.session.user_authenticated = true;

    var payload_backing: [64]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(channel_id);
    try pw.writeU32(77);
    try pw.writeU32(32768);
    try pw.writeU32(32768);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expectEqual(@as(u32, 77), chan.remote_id);
    try std.testing.expectEqual(@as(u32, 32768), chan.peer_window);
    try std.testing.expectEqual(ChannelState.Data, chan.state);
    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .AgentChannelOpen => |id| try std.testing.expectEqual(channel_id, id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: agent channel open failure emits close event" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try SshzServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const channel_id = try m.session.openAgentChannel();
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    chan.state = .OpenSent;
    m.session.user_authenticated = true;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
    try pw.writeU32(channel_id);
    try pw.writeU32(1);
    try pw.writeU32LenString("rejected");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expect(m.session.channel_table.findByLocalId(channel_id) == null);
    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .AgentChannelClosed => |id| try std.testing.expectEqual(channel_id, id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}
