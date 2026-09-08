const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const UNSAFE_TRACEDUMP = util.unsafeTracedump;
const Sshz = @import("sshz.zig").Sshz;
const SshzError = @import("sshz.zig").SshzError;
const IoError = @import("sshz.zig").IoError;
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;
const BufferReader = @import("buffer.zig").BufferReader;
const AesCtr = @import("aesctr.zig").AesCtr;
const decodePrivKey = @import("privkey.zig").decodePrivKey;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const zlib = @cImport({
    @cInclude("zlib.h");
});

pub const CommDir = enum {
    ClientToServer,
    ServerToClient,
};

// https://datatracker.ietf.org/doc/html/rfc4250#section-4.1.2
pub const MsgId = enum(u8) {
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
    SSH_MSG_USERAUTH_PK_OK = 60, // also SSH_MSG_USERAUTH_INFO_REQUEST per RFC 4256
    SSH_MSG_USERAUTH_INFO_RESPONSE = 61,
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100,
};

// RFC 4250 §4.1.2 reserves message numbers 80-127 for the connection protocol,
// which is only reachable after `ssh-userauth` succeeds.
pub const connection_protocol_msgid_min: u8 = 80;
pub const connection_protocol_msgid_max: u8 = 127;

// SSH packet header, appears before payload
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
pub const PktHdr = packed struct {
    packet_length: u32,
    padding_length: u8,
};

// Number of bytes used by PktHdr
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
pub const sizeof_PktHdr = @bitSizeOf(PktHdr) / 8;

pub fn readPktHdr(packet: []const u8) PktHdr {
    std.debug.assert(packet.len >= sizeof_PktHdr);
    return .{
        .packet_length = std.mem.readInt(u32, packet[0..4], .big),
        .padding_length = packet[4],
    };
}

fn writePktHdr(packet: []u8, hdr: PktHdr) void {
    std.debug.assert(packet.len >= sizeof_PktHdr);
    std.mem.writeInt(u32, packet[0..4], hdr.packet_length, .big);
    packet[4] = hdr.padding_length;
}

// order in which items must be hashed to produce kex hash, H
// The key exchange hash is built up piecemeal through several states
// Calling check to advance to the next state asserts if it's done in the wrong order
pub const KexHashOrder = enum { // https://datatracker.ietf.org/doc/html/rfc5656#section-4
    Init,
    V_C, // client's identification string (CR and LF excluded)
    V_S, // server's identification string (CR and LF excluded)
    I_C, // payload of the client's SSH_MSG_KEXINIT
    I_S, // payload of the server's SSH_MSG_KEXINIT
    K_S, // server's public host key
    Q_C, // client's ephemeral public key octet string
    Q_S, // server's ephemeral public key octet string
    K, // shared secret

    // calling myorder = myorder.check(next) will assert if done in the wrong order
    pub fn check(self: *const KexHashOrder, next: KexHashOrder) KexHashOrder {
        TRACE(.Debug, "KexHashOrder {any} -> {any}", .{ self, next });
        std.debug.assert(@intFromEnum(self.*) + 1 == @intFromEnum(next));
        return next;
    }
};

// RFC 4253 §6.1 requires support for uncompressed payloads of at least 32768 bytes.
// This internal bound includes packet framing, maximum padding, and the MAC.
pub const MaxSSHPacket = 35000;
pub const MaxPayload = (MaxSSHPacket - (sizeof_PktHdr + 255 + mac_algo.key_length));
pub const ChannelDataFramingLen = 1 + 4 + 4;
pub const ChannelExtendedDataFramingLen = 1 + 4 + 4 + 4;

// zlib's documented compressBound formula plus conservative Z_SYNC_FLUSH room.
pub fn zlibSyncFlushBound(input_len: usize) usize {
    return input_len +
        (input_len >> 12) +
        (input_len >> 14) +
        (input_len >> 25) +
        32;
}

fn maxChannelDataLen() usize {
    var data_len = MaxPayload - ChannelExtendedDataFramingLen;
    while (zlibSyncFlushBound(data_len + ChannelExtendedDataFramingLen) > MaxPayload) {
        data_len -= 1;
    }
    return data_len;
}

// Logical/decompressed channel bytes guaranteed to fit both DATA and
// EXTENDED_DATA after worst-case delayed-zlib expansion.
pub const MaxChannelDataLen = maxChannelDataLen();
pub const MaxIVLen = 20; // number of bytes to generate for IVs
pub const MaxKeyLen = 64; // number of bytes to generate for keys
pub const MaxIdentificationLineLen = 255;
pub const MaxPreIdentificationLines = 50;

// https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
pub const version = "SSH-2.0-SSH_ZS_0.0.1";

pub fn isValidIdentification(identification: []const u8) bool {
    const prefix = if (std.mem.startsWith(u8, identification, "SSH-2.0-"))
        "SSH-2.0-"
    else if (std.mem.startsWith(u8, identification, "SSH-1.99-"))
        "SSH-1.99-"
    else
        return false;

    const remainder = identification[prefix.len..];
    const comments_separator = std.mem.indexOfScalar(u8, remainder, ' ');
    const software_version = if (comments_separator) |index| remainder[0..index] else remainder;
    if (software_version.len == 0) return false;
    for (software_version) |byte| {
        const valid = (byte >= 0x21 and byte <= 0x2c) or (byte >= 0x2e and byte <= 0x7e);
        if (!valid) return false;
    }

    if (comments_separator) |index| {
        const comments = remainder[index + 1 ..];
        for (comments) |byte| {
            if (byte == 0 or byte == '\r' or byte == '\n') return false;
        }
        if (!std.unicode.utf8ValidateSlice(comments)) return false;
    }
    return true;
}

pub const hash_algo = std.crypto.hash.sha2.Sha256;
pub const hash_algo_name = "hmac-sha2-256";

pub const kex_algo = std.crypto.dh.X25519;
pub const kex_algo_name = "curve25519-sha256";
pub const kex_algorithms = kex_algo_name;

pub const srv_hostkey_algo = std.crypto.sign.Ed25519;
pub const srv_hostkey_algo_name = "ssh-ed25519";

pub const mac_algo = std.crypto.auth.hmac.sha2.HmacSha256;
pub const mac_algo_name = "hmac-sha2-256";
pub const mac_algorithms = mac_algo_name;

pub const enc_algo = std.crypto.core.aes.Aes256;
pub const enc_algo_name = "aes256-ctr";
pub const encryption_algorithms = enc_algo_name;
pub const AesCtrT = AesCtr(enc_algo);

pub const compression_none = "none";
pub const compression_zlib_openssh = "zlib@openssh.com";
pub const compression_algorithms = compression_zlib_openssh ++ "," ++ compression_none;

pub const AlgorithmRole = enum {
    Client,
    Server,
};

pub const AlgorithmOffers = struct {
    kex: []const u8,
    host_key: []const u8,
    encryption_c2s: []const u8,
    encryption_s2c: []const u8,
    mac_c2s: []const u8,
    mac_s2c: []const u8,
    compression_c2s: []const u8,
    compression_s2c: []const u8,
};

pub fn localAlgorithmOffers(host_key_algorithms: []const u8) AlgorithmOffers {
    return .{
        .kex = kex_algorithms,
        .host_key = host_key_algorithms,
        .encryption_c2s = encryption_algorithms,
        .encryption_s2c = encryption_algorithms,
        .mac_c2s = mac_algorithms,
        .mac_s2c = mac_algorithms,
        .compression_c2s = compression_algorithms,
        .compression_s2c = compression_algorithms,
    };
}

pub const KexInit = struct {
    offers: AlgorithmOffers,
    language_c2s: []const u8,
    language_s2c: []const u8,
    first_kex_packet_follows: bool,
};

pub const NegotiatedAlgorithms = struct {
    host_key: []const u8,
    compression_c2s: CompressionAlgorithm,
    compression_s2c: CompressionAlgorithm,
    ignore_next_peer_packet: bool,
};

pub const MaxNameListEntries: usize = 64;

pub fn isValidNameList(namelist: []const u8, require_non_empty: bool) bool {
    if (namelist.len == 0) return !require_non_empty;

    var entry_count: usize = 0;
    var names = std.mem.splitScalar(u8, namelist, ',');
    while (names.next()) |name| {
        entry_count += 1;
        if (entry_count > MaxNameListEntries) return false;
        if (name.len == 0) return false;
        for (name) |byte| {
            if (byte < 0x21 or byte > 0x7e or byte == ',') return false;
        }

        var prior = std.mem.splitScalar(u8, namelist, ',');
        while (prior.next()) |candidate| {
            if (candidate.ptr == name.ptr) break;
            if (std.mem.eql(u8, candidate, name)) return false;
        }
    }
    return true;
}

pub fn nameListContains(namelist: []const u8, target: []const u8) bool {
    var names = std.mem.splitScalar(u8, namelist, ',');
    while (names.next()) |name| {
        if (std.mem.eql(u8, name, target)) return true;
    }
    return false;
}

fn firstName(namelist: []const u8) []const u8 {
    return std.mem.sliceTo(namelist, ',');
}

fn selectClientPreferred(client_namelist: []const u8, server_namelist: []const u8) ?[]const u8 {
    var client_names = std.mem.splitScalar(u8, client_namelist, ',');
    while (client_names.next()) |client_name| {
        if (nameListContains(server_namelist, client_name)) return client_name;
    }
    return null;
}

pub fn readKexInit(rdr: *BufferReader) SshzError!KexInit {
    _ = try rdr.readBytes(16);
    const result: KexInit = .{
        .offers = .{
            .kex = try rdr.readU32LenString(),
            .host_key = try rdr.readU32LenString(),
            .encryption_c2s = try rdr.readU32LenString(),
            .encryption_s2c = try rdr.readU32LenString(),
            .mac_c2s = try rdr.readU32LenString(),
            .mac_s2c = try rdr.readU32LenString(),
            .compression_c2s = try rdr.readU32LenString(),
            .compression_s2c = try rdr.readU32LenString(),
        },
        .language_c2s = try rdr.readU32LenString(),
        .language_s2c = try rdr.readU32LenString(),
        .first_kex_packet_follows = try rdr.readBoolean(),
    };
    _ = try rdr.readU32();
    if (rdr.off != rdr.payload.len) return IoError.UnexpectedResponse;

    inline for (std.meta.fields(AlgorithmOffers)) |field| {
        if (!isValidNameList(@field(result.offers, field.name), true)) {
            return IoError.AlgorithmNegotiationFailed;
        }
    }
    if (!isValidNameList(result.language_c2s, false) or
        !isValidNameList(result.language_s2c, false))
    {
        return IoError.AlgorithmNegotiationFailed;
    }
    return result;
}

pub fn negotiateAlgorithms(
    peer: KexInit,
    role: AlgorithmRole,
    local_host_key_algorithms: []const u8,
) SshzError!NegotiatedAlgorithms {
    inline for (std.meta.fields(AlgorithmOffers)) |field| {
        if (!isValidNameList(@field(peer.offers, field.name), true)) {
            return IoError.AlgorithmNegotiationFailed;
        }
    }
    if (!isValidNameList(peer.language_c2s, false) or
        !isValidNameList(peer.language_s2c, false))
    {
        return IoError.AlgorithmNegotiationFailed;
    }
    if (!isValidNameList(local_host_key_algorithms, true)) {
        return IoError.AlgorithmNegotiationFailed;
    }

    const local = localAlgorithmOffers(local_host_key_algorithms);
    const client = if (role == .Client) local else peer.offers;
    const server = if (role == .Client) peer.offers else local;

    const selected_kex = selectClientPreferred(client.kex, server.kex) orelse
        return IoError.AlgorithmNegotiationFailed;
    const selected_host_key = selectClientPreferred(client.host_key, server.host_key) orelse
        return IoError.AlgorithmNegotiationFailed;
    _ = selectClientPreferred(client.encryption_c2s, server.encryption_c2s) orelse
        return IoError.AlgorithmNegotiationFailed;
    _ = selectClientPreferred(client.encryption_s2c, server.encryption_s2c) orelse
        return IoError.AlgorithmNegotiationFailed;
    _ = selectClientPreferred(client.mac_c2s, server.mac_c2s) orelse
        return IoError.AlgorithmNegotiationFailed;
    _ = selectClientPreferred(client.mac_s2c, server.mac_s2c) orelse
        return IoError.AlgorithmNegotiationFailed;
    const selected_compression_c2s = selectClientPreferred(client.compression_c2s, server.compression_c2s) orelse
        return IoError.AlgorithmNegotiationFailed;
    const selected_compression_s2c = selectClientPreferred(client.compression_s2c, server.compression_s2c) orelse
        return IoError.AlgorithmNegotiationFailed;

    const peer_guessed_correctly =
        std.mem.eql(u8, firstName(peer.offers.kex), selected_kex) and
        std.mem.eql(u8, firstName(peer.offers.host_key), selected_host_key);

    return .{
        .host_key = selected_host_key,
        .compression_c2s = CompressionAlgorithm.fromName(selected_compression_c2s) orelse unreachable,
        .compression_s2c = CompressionAlgorithm.fromName(selected_compression_s2c) orelse unreachable,
        .ignore_next_peer_packet = peer.first_kex_packet_follows and !peer_guessed_correctly,
    };
}

pub const channel_type_session = "session";
pub const channel_type_auth_agent_openssh = "auth-agent@openssh.com";
pub const channel_type_auth_agent = "auth-agent";
pub const channel_request_auth_agent = "auth-agent-req@openssh.com";
pub const channel_request_exit_status = "exit-status";
pub const channel_request_exit_signal = "exit-signal";

pub fn isAgentChannelType(channel_type: []const u8) bool {
    return std.mem.eql(u8, channel_type, channel_type_auth_agent_openssh) or
        std.mem.eql(u8, channel_type, channel_type_auth_agent);
}

// Note, the buffers are not used for storage, they're just passed forward to signal to receiver where the data can be found
pub const IoSessionState = union(enum) {
    Init,
    Idle,
    VersionWrite,
    VersionReadLine,
    VersionReadLineChar: []const u8,
    VersionReadLineCompletion: []const u8,
    WriteCompletePreserveState,
    GlobalRequestWriteComplete,
    ChannelWriteComplete: u32,
    ChannelControlComplete: u32,
    ReadPktHdr,
    ReadPktBody: []const u8,
    ReadPktCompletion: []const u8,
};

pub const CompressionAlgorithm = enum {
    None,
    ZlibOpenSsh,

    pub fn name(self: CompressionAlgorithm) []const u8 {
        return switch (self) {
            .None => compression_none,
            .ZlibOpenSsh => compression_zlib_openssh,
        };
    }

    pub fn fromName(name_bytes: []const u8) ?CompressionAlgorithm {
        if (std.mem.eql(u8, name_bytes, compression_none)) return .None;
        if (std.mem.eql(u8, name_bytes, compression_zlib_openssh)) return .ZlibOpenSsh;
        return null;
    }
};

pub fn selectCompressionAlgorithm(client_namelist: []const u8, server_namelist: []const u8) ?CompressionAlgorithm {
    if (!isValidNameList(client_namelist, true) or !isValidNameList(server_namelist, true)) return null;
    const selected = selectClientPreferred(client_namelist, server_namelist) orelse return null;
    return CompressionAlgorithm.fromName(selected);
}

pub const CompressionState = struct {
    const Self = @This();

    algorithm: CompressionAlgorithm = .None,
    pending_algorithm: ?CompressionAlgorithm = null,
    active: bool = false,
    deflate_initialized: bool = false,
    inflate_initialized: bool = false,
    deflate_stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream),
    inflate_stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream),

    pub fn queueAlgorithm(self: *Self, algorithm: CompressionAlgorithm) void {
        self.pending_algorithm = algorithm;
    }

    pub fn applyPendingAlgorithm(self: *Self) void {
        if (self.pending_algorithm) |algorithm| {
            self.endStreams();
            self.algorithm = algorithm;
            self.active = false;
            self.pending_algorithm = null;
        }
    }

    pub fn activateDeflate(self: *Self) SshzError!void {
        switch (self.algorithm) {
            .None => {},
            .ZlibOpenSsh => {
                if (!self.deflate_initialized) {
                    try self.initDeflate();
                }
                self.active = true;
            },
        }
    }

    pub fn activateInflate(self: *Self) SshzError!void {
        switch (self.algorithm) {
            .None => {},
            .ZlibOpenSsh => {
                if (!self.inflate_initialized) {
                    try self.initInflate();
                }
                self.active = true;
            },
        }
    }

    pub fn compressPayload(self: *Self, input: []const u8, output: []u8) SshzError![]const u8 {
        if (!self.active or self.algorithm == .None) return input;
        if (input.len > MaxPayload or output.len == 0) return IoError.tooBig;

        switch (self.algorithm) {
            .None => return input,
            .ZlibOpenSsh => {
                if (!self.deflate_initialized) {
                    try self.initDeflate();
                }
                self.deflate_stream.next_in = @ptrCast(@constCast(input.ptr));
                self.deflate_stream.avail_in = @intCast(input.len);
                self.deflate_stream.next_out = @ptrCast(output.ptr);
                self.deflate_stream.avail_out = @intCast(output.len);

                const rc = zlib.deflate(&self.deflate_stream, zlib.Z_SYNC_FLUSH);
                if (rc != zlib.Z_OK) return IoError.UnexpectedResponse;
                if (self.deflate_stream.avail_in != 0 or self.deflate_stream.avail_out == 0) return IoError.tooBig;

                return output[0 .. output.len - self.deflate_stream.avail_out];
            },
        }
    }

    pub fn decompressPayload(self: *Self, input: []const u8, output: []u8) SshzError![]const u8 {
        if (!self.active or self.algorithm == .None) return input;
        if (output.len == 0) return IoError.tooBig;

        switch (self.algorithm) {
            .None => return input,
            .ZlibOpenSsh => {
                if (!self.inflate_initialized) {
                    try self.initInflate();
                }
                self.inflate_stream.next_in = @ptrCast(@constCast(input.ptr));
                self.inflate_stream.avail_in = @intCast(input.len);
                self.inflate_stream.next_out = @ptrCast(output.ptr);
                self.inflate_stream.avail_out = @intCast(output.len);

                const rc = zlib.inflate(&self.inflate_stream, zlib.Z_SYNC_FLUSH);
                if (rc != zlib.Z_OK) {
                    if (rc == zlib.Z_BUF_ERROR and self.inflate_stream.avail_out == 0) return IoError.tooBig;
                    return IoError.InvalidPacketSize;
                }
                if (self.inflate_stream.avail_in != 0) return IoError.tooBig;
                if (self.inflate_stream.avail_out == 0) {
                    var overflow_probe: [1]u8 = undefined;
                    self.inflate_stream.next_out = @ptrCast(&overflow_probe);
                    self.inflate_stream.avail_out = 1;
                    const probe_rc = zlib.inflate(&self.inflate_stream, zlib.Z_SYNC_FLUSH);
                    if (self.inflate_stream.avail_out == 0) return IoError.tooBig;
                    if (probe_rc != zlib.Z_OK and probe_rc != zlib.Z_BUF_ERROR)
                        return IoError.InvalidPacketSize;
                    return output;
                }

                return output[0 .. output.len - self.inflate_stream.avail_out];
            },
        }
    }

    pub fn deinit(self: *Self) void {
        self.endStreams();
        self.algorithm = .None;
        self.pending_algorithm = null;
        self.active = false;
    }

    fn initDeflate(self: *Self) SshzError!void {
        self.deflate_stream = std.mem.zeroes(zlib.z_stream);
        const rc = zlib.deflateInit_(&self.deflate_stream, zlib.Z_DEFAULT_COMPRESSION, zlib.ZLIB_VERSION, @sizeOf(zlib.z_stream));
        if (rc != zlib.Z_OK) return IoError.UnexpectedResponse;
        self.deflate_initialized = true;
    }

    fn initInflate(self: *Self) SshzError!void {
        self.inflate_stream = std.mem.zeroes(zlib.z_stream);
        const rc = zlib.inflateInit_(&self.inflate_stream, zlib.ZLIB_VERSION, @sizeOf(zlib.z_stream));
        if (rc != zlib.Z_OK) return IoError.UnexpectedResponse;
        self.inflate_initialized = true;
    }

    fn endStreams(self: *Self) void {
        if (self.deflate_initialized) {
            _ = zlib.deflateEnd(&self.deflate_stream);
            self.deflate_initialized = false;
        }
        if (self.inflate_initialized) {
            _ = zlib.inflateEnd(&self.inflate_stream);
            self.inflate_initialized = false;
        }
        self.deflate_stream = std.mem.zeroes(zlib.z_stream);
        self.inflate_stream = std.mem.zeroes(zlib.z_stream);
    }
};

pub const KeyDataUni = struct {
    iv: [MaxIVLen]u8 = undefined,
    key: [MaxKeyLen]u8 = undefined,
    mackey: [MaxKeyLen]u8 = undefined,
    seq: u32,
    epoch: u64 = 0,
    encrypted_bytes: u64 = 0,
    encrypted_packets: u64 = 0,
    activated_at_monotonic_tick: ?u64 = null,
    aesctr: AesCtrT = undefined,
    compression: CompressionState = .{},

    pub fn activateEpoch(self: *KeyDataUni, previous_epoch: u64, activated_at: ?u64) SshzError!void {
        if (previous_epoch == std.math.maxInt(u64)) return IoError.KeyLifetimeExceeded;
        self.epoch = previous_epoch + 1;
        self.encrypted_bytes = 0;
        self.encrypted_packets = 0;
        self.activated_at_monotonic_tick = activated_at;
    }

    pub fn accountEncryptedPacket(self: *KeyDataUni, packet_len: usize) SshzError!void {
        self.encrypted_bytes = std.math.add(u64, self.encrypted_bytes, packet_len) catch
            return IoError.KeyLifetimeExceeded;
        self.encrypted_packets = std.math.add(u64, self.encrypted_packets, 1) catch
            return IoError.KeyLifetimeExceeded;
    }

    pub fn clear(self: *KeyDataUni) void {
        self.compression.deinit();
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.mackey);
        self.aesctr.clear();
        self.seq = 0;
        self.epoch = 0;
        self.encrypted_bytes = 0;
        self.encrypted_packets = 0;
        self.activated_at_monotonic_tick = null;
    }
};

fn deriveKeyMaterial(out: []u8, data_kh: []const u8, discriminator: u8, session_id: []const u8) void {
    var hasher = hash_algo.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hasher));
    var digest: [hash_algo.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);

    hasher.update(data_kh);
    hasher.update(&.{discriminator});
    hasher.update(session_id);
    hasher.final(&digest);

    var written: usize = @min(out.len, digest.len);
    @memcpy(out[0..written], digest[0..written]);
    while (written < out.len) {
        std.crypto.secureZero(u8, std.mem.asBytes(&hasher));
        hasher = hash_algo.init(.{});
        hasher.update(data_kh);
        hasher.update(out[0..written]);
        hasher.final(&digest);
        const take: usize = @min(out.len - written, digest.len);
        @memcpy(out[written .. written + take], digest[0..take]);
        written += take;
    }
}

pub const KeyDataBi = struct {
    const Self = @This();

    c2s: KeyDataUni,
    s2c: KeyDataUni,

    pub fn init() Self {
        return Self{
            .c2s = .{ .seq = 0 },
            .s2c = .{ .seq = 0 },
        };
    }

    pub fn clear(self: *Self) void {
        self.c2s.clear();
        self.s2c.clear();
    }

    // generate session keys from shared secret
    pub fn genKeys(self: *Self, H: [hash_algo.digest_length]u8, shared_secret_k: [kex_algo.shared_length]u8, session_id: [hash_algo.digest_length]u8) !void {
        // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
        // The inputs are borrowed from session-owned state; only the encoded
        // K || H scratch and derived state created here are owned here.
        errdefer self.clear();

        // prepare contact(K,H) = K:mpint concat H:raw
        var backing: [4 + kex_algo.shared_length + 1 + hash_algo.digest_length]u8 = undefined; // 4 for len, 1 for possible padding
        defer std.crypto.secureZero(u8, &backing);
        var khbuf = BufferWriter.init(&backing, 0);
        try khbuf.writeMpint(&shared_secret_k); // K
        try khbuf.writeBytes(&H); // H
        const data_kh = khbuf.payload;

        // c2s.iv
        deriveKeyMaterial(&self.c2s.iv, data_kh, 'A', &session_id);
        UNSAFE_TRACEDUMP(.Debug, "c2s.iv", .{}, &self.c2s.iv);

        // s2c.iv
        deriveKeyMaterial(&self.s2c.iv, data_kh, 'B', &session_id);
        UNSAFE_TRACEDUMP(.Debug, "s2c.iv", .{}, &self.s2c.iv);

        // c2s.key
        deriveKeyMaterial(&self.c2s.key, data_kh, 'C', &session_id);
        UNSAFE_TRACEDUMP(.Debug, "c2s.key", .{}, &self.c2s.key);

        // s2c.key
        deriveKeyMaterial(&self.s2c.key, data_kh, 'D', &session_id);
        UNSAFE_TRACEDUMP(.Debug, "s2c.key", .{}, &self.s2c.key);

        // c2s.mackey
        deriveKeyMaterial(&self.c2s.mackey, data_kh, 'E', &session_id);
        UNSAFE_TRACEDUMP(.Debug, "c2s.mackey", .{}, &self.c2s.mackey);

        // s2c.mackey
        deriveKeyMaterial(&self.s2c.mackey, data_kh, 'F', &session_id);
        UNSAFE_TRACEDUMP(.Debug, "s2c.mackey", .{}, &self.s2c.mackey);

        // setup aesctrs
        self.c2s.aesctr = AesCtrT.init(self.c2s.iv[0..AesCtrT.iv_size].*, self.c2s.key[0..AesCtrT.key_size].*);
        self.s2c.aesctr = AesCtrT.init(self.s2c.iv[0..AesCtrT.iv_size].*, self.s2c.key[0..AesCtrT.key_size].*);
    }
};

pub fn wrapPkt(rand: *std.Random, encrypted: bool, keysuni: *KeyDataUni, buffer: *BufferWriter, iobuf: []u8) SshzError![]const u8 {
    return wrapPayload(rand, encrypted, keysuni, buffer.active(), iobuf);
}

pub fn wrapPayload(rand: *std.Random, encrypted: bool, keysuni: *KeyDataUni, payload: []const u8, iobuf: []u8) SshzError![]const u8 {
    // https://datatracker.ietf.org/doc/html/rfc4253#section-6
    if (payload.len > MaxPayload) return IoError.tooBig;
    if (keysuni.seq == std.math.maxInt(u32)) return IoError.KeyLifetimeExceeded;

    var compressed_payload_buf: [MaxPayload]u8 = undefined;
    defer std.crypto.secureZero(u8, &compressed_payload_buf);
    const packet_payload = try keysuni.compression.compressPayload(payload, &compressed_payload_buf);
    if (packet_payload.len > MaxPayload) return IoError.tooBig;

    // pad such that whole packet (payload + hdr) is multiple of block_size
    const buffer_len = packet_payload.len;
    var padding_length: u8 = @intCast(AesCtrT.block_size - (buffer_len + sizeof_PktHdr) % AesCtrT.block_size);
    if (padding_length < 4) {
        padding_length += @intCast(AesCtrT.block_size);
    }

    const packet_len = sizeof_PktHdr + buffer_len + padding_length;
    if (packet_len > MaxSSHPacket or packet_len > iobuf.len) return IoError.tooBig;
    if (encrypted and packet_len + mac_algo.key_length > iobuf.len) return IoError.tooBig;

    // construct header
    const hdr: PktHdr = .{
        .packet_length = @intCast(buffer_len + padding_length + 1),
        .padding_length = @intCast(padding_length),
    };
    writePktHdr(iobuf[0..sizeof_PktHdr], hdr);
    std.mem.copyForwards(u8, iobuf[sizeof_PktHdr .. sizeof_PktHdr + packet_payload.len], packet_payload);

    var rndbuf: [255]u8 = undefined; // block_size would do
    rand.bytes(rndbuf[0..padding_length]);
    @memcpy(iobuf[sizeof_PktHdr + packet_payload.len .. packet_len], rndbuf[0..padding_length]);
    if (encrypted) {
        var out: [MaxSSHPacket]u8 = undefined;

        UNSAFE_TRACEDUMP(.Debug, "sendbuffer enc:plaintext", .{}, iobuf[0..packet_len]);
        keysuni.aesctr.encrypt(iobuf[0..packet_len], out[0..packet_len]) catch
            return IoError.KeyLifetimeExceeded;

        var mac: [mac_algo.key_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &mac);
        var m = mac_algo.init(keysuni.mackey[0..mac_algo.key_length]);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&m));
        const seq = std.mem.nativeTo(u32, keysuni.seq, .big);
        m.update(std.mem.asBytes(&seq));
        m.update(iobuf[0..packet_len]); // plaintext
        m.final(&mac);

        UNSAFE_TRACEDUMP(.Debug, "mackey", .{}, keysuni.mackey[0..mac_algo.key_length]);
        UNSAFE_TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
        UNSAFE_TRACEDUMP(.Debug, "macdata", .{}, iobuf[0..packet_len]);

        @memcpy(out[packet_len .. packet_len + mac_algo.key_length], &mac);
        const out_len = packet_len + mac_algo.key_length;

        // Copy encrypted packet plus MAC back to the caller's output buffer.
        @memcpy(iobuf[0..out_len], out[0..out_len]);

        UNSAFE_TRACEDUMP(.Debug, "enc send", .{}, iobuf[0..out_len]);

        keysuni.seq += 1;
        try keysuni.accountEncryptedPacket(packet_len);
        return iobuf[0..out_len];
    } else {
        keysuni.seq += 1;
        return iobuf[0..packet_len];
    }
}

test "packet sequence hard bound fails before wrapping" {
    var prng = std.Random.DefaultPrng.init(91);
    var rand = prng.random();
    var keys = KeyDataUni{ .seq = std.math.maxInt(u32) };
    var output: [MaxSSHPacket]u8 = undefined;
    try std.testing.expectError(
        IoError.KeyLifetimeExceeded,
        wrapPayload(&rand, false, &keys, &.{@intFromEnum(MsgId.SSH_MSG_IGNORE)}, &output),
    );
    try std.testing.expectEqual(std.math.maxInt(u32), keys.seq);
}

test "identification accepts valid UTF-8 comments" {
    try std.testing.expect(isValidIdentification("SSH-2.0-server café 🚀"));
}

test "identification accepts SSH 1.99 compatibility version" {
    try std.testing.expect(isValidIdentification("SSH-1.99-server compatibility"));
}

test "identification rejects hyphen in softwareversion" {
    try std.testing.expect(!isValidIdentification("SSH-2.0-server-name comment"));
}

test "identification rejects invalid UTF-8 and forbidden comment bytes" {
    try std.testing.expect(!isValidIdentification("SSH-2.0-server \x80"));
    try std.testing.expect(!isValidIdentification("SSH-2.0-server comment\x00text"));
    try std.testing.expect(!isValidIdentification("SSH-2.0-server comment\rtext"));
    try std.testing.expect(!isValidIdentification("SSH-2.0-server comment\ntext"));
}

test "MsgId enum values match SSH RFC" {
    // RFC 4253 transport layer messages
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(MsgId.SSH_MSG_DISCONNECT));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(MsgId.SSH_MSG_IGNORE));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(MsgId.SSH_MSG_UNIMPLEMENTED));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(MsgId.SSH_MSG_DEBUG));

    // RFC 4254 channel messages
    try std.testing.expectEqual(@as(u8, 80), @intFromEnum(MsgId.SSH_MSG_GLOBAL_REQUEST));
    try std.testing.expectEqual(@as(u8, 81), @intFromEnum(MsgId.SSH_MSG_REQUEST_SUCCESS));
    try std.testing.expectEqual(@as(u8, 82), @intFromEnum(MsgId.SSH_MSG_REQUEST_FAILURE));
    try std.testing.expectEqual(@as(u8, 90), @intFromEnum(MsgId.SSH_MSG_CHANNEL_OPEN));
    try std.testing.expectEqual(@as(u8, 94), @intFromEnum(MsgId.SSH_MSG_CHANNEL_DATA));
    try std.testing.expectEqual(@as(u8, 96), @intFromEnum(MsgId.SSH_MSG_CHANNEL_EOF));
    try std.testing.expectEqual(@as(u8, 97), @intFromEnum(MsgId.SSH_MSG_CHANNEL_CLOSE));
}

test "MaxPayload is reasonable" {
    try std.testing.expect(MaxPayload > 0);
    try std.testing.expect(MaxPayload < MaxSSHPacket);
}

test "MaxChannelDataLen accounts for extended framing and zlib expansion" {
    try std.testing.expect(
        zlibSyncFlushBound(MaxChannelDataLen + ChannelExtendedDataFramingLen) <= MaxPayload,
    );
    try std.testing.expect(
        zlibSyncFlushBound(MaxChannelDataLen + 1 + ChannelExtendedDataFramingLen) > MaxPayload,
    );
    try std.testing.expect(MaxChannelDataLen > 0);
    try std.testing.expect(MaxChannelDataLen >= 32768);
}

test "agent forwarding channel type aliases" {
    try std.testing.expect(isAgentChannelType(channel_type_auth_agent_openssh));
    try std.testing.expect(isAgentChannelType(channel_type_auth_agent));
    try std.testing.expect(!isAgentChannelType(channel_type_session));
}

test "compression algorithm selection follows client preference" {
    try std.testing.expectEqual(CompressionAlgorithm.ZlibOpenSsh, selectCompressionAlgorithm(compression_algorithms, compression_algorithms).?);
    try std.testing.expectEqual(CompressionAlgorithm.None, selectCompressionAlgorithm("none,zlib@openssh.com", compression_algorithms).?);
    try std.testing.expectEqual(CompressionAlgorithm.None, selectCompressionAlgorithm(compression_algorithms, "none").?);
    try std.testing.expect(selectCompressionAlgorithm("zstd@openssh.com", compression_algorithms) == null);
}

fn testKexInit() KexInit {
    return .{
        .offers = .{
            .kex = kex_algorithms,
            .host_key = srv_hostkey_algo_name,
            .encryption_c2s = encryption_algorithms,
            .encryption_s2c = encryption_algorithms,
            .mac_c2s = mac_algorithms,
            .mac_s2c = mac_algorithms,
            .compression_c2s = compression_algorithms,
            .compression_s2c = compression_algorithms,
        },
        .language_c2s = "",
        .language_s2c = "",
        .first_kex_packet_follows = false,
    };
}

test "SSH name-list grammar rejects empty elements invalid bytes and duplicates" {
    try std.testing.expect(isValidNameList("", false));
    try std.testing.expect(!isValidNameList("", true));
    try std.testing.expect(isValidNameList("curve25519-sha256,aes256-ctr", true));
    try std.testing.expect(!isValidNameList(",aes256-ctr", true));
    try std.testing.expect(!isValidNameList("aes256-ctr,", true));
    try std.testing.expect(!isValidNameList("aes256-ctr,,none", true));
    try std.testing.expect(!isValidNameList("aes256-ctr,aes256-ctr", true));
    try std.testing.expect(!isValidNameList("aes256-ctr,\x7f", true));
    try std.testing.expect(!isValidNameList("aes256 ctr", true));

    var too_many: [MaxNameListEntries * 2 + 1]u8 = undefined;
    for (0..MaxNameListEntries + 1) |index| {
        if (index != 0) too_many[index * 2 - 1] = ',';
        var name: u8 = @intCast(0x21 + index);
        if (name >= ',') name += 1;
        too_many[index * 2] = name;
    }
    try std.testing.expect(!isValidNameList(&too_many, true));
}

test "algorithm negotiation always follows client preference for both roles" {
    var server_kexinit = testKexInit();
    server_kexinit.offers.kex = "unsupported-kex,curve25519-sha256";
    server_kexinit.offers.host_key = "rsa-sha2-256,ssh-ed25519";
    server_kexinit.offers.compression_c2s = "none,zlib@openssh.com";
    server_kexinit.offers.compression_s2c = "none,zlib@openssh.com";
    server_kexinit.first_kex_packet_follows = true;

    const as_client = try negotiateAlgorithms(
        server_kexinit,
        .Client,
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
    );
    try std.testing.expectEqualStrings("ssh-ed25519", as_client.host_key);
    try std.testing.expectEqual(CompressionAlgorithm.ZlibOpenSsh, as_client.compression_c2s);
    try std.testing.expect(as_client.ignore_next_peer_packet);

    var client_kexinit = testKexInit();
    client_kexinit.offers.host_key = "rsa-sha2-256,rsa-sha2-512";
    client_kexinit.offers.compression_c2s = "none,zlib@openssh.com";
    client_kexinit.offers.compression_s2c = "none,zlib@openssh.com";
    client_kexinit.first_kex_packet_follows = true;

    const as_server = try negotiateAlgorithms(
        client_kexinit,
        .Server,
        "rsa-sha2-512,rsa-sha2-256",
    );
    try std.testing.expectEqualStrings("rsa-sha2-256", as_server.host_key);
    try std.testing.expectEqual(CompressionAlgorithm.None, as_server.compression_c2s);
    try std.testing.expect(!as_server.ignore_next_peer_packet);
}

test "algorithm negotiation fails closed for every required category" {
    inline for (std.meta.fields(AlgorithmOffers)) |field| {
        var peer = testKexInit();
        @field(peer.offers, field.name) = "unsupported-only";
        try std.testing.expectError(
            IoError.AlgorithmNegotiationFailed,
            negotiateAlgorithms(peer, .Server, srv_hostkey_algo_name),
        );
        try std.testing.expectError(
            IoError.AlgorithmNegotiationFailed,
            negotiateAlgorithms(
                peer,
                .Client,
                "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
            ),
        );
    }

    var duplicate = testKexInit();
    duplicate.offers.kex = "curve25519-sha256,curve25519-sha256";
    try std.testing.expectError(
        IoError.AlgorithmNegotiationFailed,
        negotiateAlgorithms(duplicate, .Server, srv_hostkey_algo_name),
    );
}

fn writeTestKexInitBody(writer: *BufferWriter, kexinit: KexInit) !void {
    try writer.writeBytes(&(.{0x5a} ** 16));
    inline for (std.meta.fields(AlgorithmOffers)) |field| {
        try writer.writeU32LenString(@field(kexinit.offers, field.name));
    }
    try writer.writeU32LenString(kexinit.language_c2s);
    try writer.writeU32LenString(kexinit.language_s2c);
    try writer.writeBoolean(kexinit.first_kex_packet_follows);
    try writer.writeU32(0);
}

test "KEXINIT parser validates name-lists and exact framing" {
    var backing: [512]u8 = undefined;
    var writer = BufferWriter.init(&backing, 0);
    try writeTestKexInitBody(&writer, testKexInit());
    var reader = BufferReader.init(writer.active());
    _ = try readKexInit(&reader);

    var malformed = testKexInit();
    malformed.offers.kex = "curve25519-sha256,curve25519-sha256";
    writer = BufferWriter.init(&backing, 0);
    try writeTestKexInitBody(&writer, malformed);
    reader = BufferReader.init(writer.active());
    try std.testing.expectError(IoError.AlgorithmNegotiationFailed, readKexInit(&reader));

    writer = BufferWriter.init(&backing, 0);
    try writeTestKexInitBody(&writer, testKexInit());
    try writer.writeU8(0);
    reader = BufferReader.init(writer.active());
    try std.testing.expectError(IoError.UnexpectedResponse, readKexInit(&reader));
}

test "zlib openssh compression streams round trip flushed packets" {
    var compressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer compressor.deinit();
    var decompressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer decompressor.deinit();

    try compressor.activateDeflate();
    try decompressor.activateInflate();

    var compressed: [MaxPayload]u8 = undefined;
    var decompressed: [MaxPayload]u8 = undefined;

    const payload1 = "hello hello hello hello hello";
    const compressed1 = try compressor.compressPayload(payload1, &compressed);
    const decompressed1 = try decompressor.decompressPayload(compressed1, &decompressed);
    try std.testing.expectEqualStrings(payload1, decompressed1);

    const payload2 = "second packet reuses the same zlib stream";
    const compressed2 = try compressor.compressPayload(payload2, &compressed);
    const decompressed2 = try decompressor.decompressPayload(compressed2, &decompressed);
    try std.testing.expectEqualStrings(payload2, decompressed2);
}

fn incompressibleTestByte(index: usize) u8 {
    var value: u32 = @intCast(index);
    value = value *% 1664525 +% 1013904223;
    return @truncate(value >> 24);
}

fn expectExactBoundCompressedChannelPayload(extended: bool) !void {
    var logical_data: [MaxChannelDataLen]u8 = undefined;
    for (&logical_data, 0..) |*byte, index| byte.* = incompressibleTestByte(index);

    var payload_backing: [MaxPayload]u8 = undefined;
    var payload = BufferWriter.init(&payload_backing, 0);
    try payload.writeU8(@intFromEnum(if (extended) MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA else MsgId.SSH_MSG_CHANNEL_DATA));
    try payload.writeU32(7);
    if (extended) try payload.writeU32(1);
    try payload.writeU32LenString(&logical_data);

    var sender = KeyDataUni{ .seq = 0, .compression = .{ .algorithm = .ZlibOpenSsh } };
    defer sender.clear();
    try sender.compression.activateDeflate();
    var prng = std.Random.DefaultPrng.init(42);
    var rand = prng.random();
    var packet_buf: [MaxSSHPacket]u8 = undefined;
    const packet = try wrapPayload(&rand, false, &sender, payload.active(), &packet_buf);

    const hdr = readPktHdr(packet[0..sizeof_PktHdr]);
    const compressed_len: usize = @intCast(hdr.packet_length - hdr.padding_length - 1);
    var receiver = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer receiver.deinit();
    try receiver.activateInflate();
    var decompressed: [MaxPayload]u8 = undefined;
    const decoded = try receiver.decompressPayload(
        packet[sizeof_PktHdr .. sizeof_PktHdr + compressed_len],
        &decompressed,
    );
    try std.testing.expectEqualSlices(u8, payload.active(), decoded);
}

test "exact advertised DATA bound is encodable with incompressible zlib" {
    try expectExactBoundCompressedChannelPayload(false);
}

test "exact advertised EXTENDED_DATA bound is encodable with incompressible zlib" {
    try expectExactBoundCompressedChannelPayload(true);
}

test "zlib openssh decompression rejects invalid data" {
    var decompressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer decompressor.deinit();
    try decompressor.activateInflate();

    var output: [MaxPayload]u8 = undefined;
    try std.testing.expectError(IoError.InvalidPacketSize, decompressor.decompressPayload("not a zlib stream", &output));
}

fn expectDecompressionBoundary(input_len: usize, output_len: usize, expect_overflow: bool) !void {
    var input: [65]u8 = .{'A'} ** 65;
    var compressed: [MaxPayload]u8 = undefined;
    var output: [64]u8 = undefined;
    var compressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer compressor.deinit();
    var decompressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer decompressor.deinit();
    try compressor.activateDeflate();
    try decompressor.activateInflate();
    const encoded = try compressor.compressPayload(input[0..input_len], &compressed);
    if (expect_overflow) {
        try std.testing.expectError(IoError.tooBig, decompressor.decompressPayload(encoded, output[0..output_len]));
    } else {
        const decoded = try decompressor.decompressPayload(encoded, output[0..output_len]);
        try std.testing.expectEqual(input_len, decoded.len);
        try std.testing.expectEqualSlices(u8, input[0..input_len], decoded);
    }
}

test "zlib decompression output limit enforces below at and above" {
    try expectDecompressionBoundary(63, 64, false);
    try expectDecompressionBoundary(64, 64, false);
    try expectDecompressionBoundary(65, 64, true);
}

test "wrapPayload preserves uncompressed payload with none compression" {
    var prng = std.Random.DefaultPrng.init(42);
    var keys = KeyDataUni{ .seq = 0 };
    defer keys.clear();
    var rand = prng.random();

    var iobuf: [MaxSSHPacket]u8 = undefined;
    const payload = "plain ssh payload";
    const packet = try wrapPayload(&rand, false, &keys, payload, &iobuf);

    const hdr = readPktHdr(packet[0..sizeof_PktHdr]);
    const payload_len = hdr.packet_length - hdr.padding_length - 1;
    try std.testing.expectEqualStrings(payload, packet[sizeof_PktHdr .. sizeof_PktHdr + payload_len]);
}

test "wrapPayload compresses active zlib openssh payloads" {
    var prng = std.Random.DefaultPrng.init(42);
    var sender = KeyDataUni{ .seq = 0, .compression = .{ .algorithm = .ZlibOpenSsh } };
    defer sender.clear();
    var receiver = KeyDataUni{ .seq = 0, .compression = .{ .algorithm = .ZlibOpenSsh } };
    defer receiver.clear();
    try sender.compression.activateDeflate();
    try receiver.compression.activateInflate();
    var rand = prng.random();

    var iobuf: [MaxSSHPacket]u8 = undefined;
    const payload = "compressed ssh payload compressed ssh payload compressed ssh payload";
    const packet = try wrapPayload(&rand, false, &sender, payload, &iobuf);

    const hdr = readPktHdr(packet[0..sizeof_PktHdr]);
    const compressed_len = hdr.packet_length - hdr.padding_length - 1;
    const compressed_payload = packet[sizeof_PktHdr .. sizeof_PktHdr + compressed_len];
    try std.testing.expect(!std.mem.eql(u8, payload, compressed_payload));

    var decompressed: [MaxPayload]u8 = undefined;
    const restored = try receiver.compression.decompressPayload(compressed_payload, &decompressed);
    try std.testing.expectEqualStrings(payload, restored);
}

test "KeyDataBi.clear zeros all key material" {
    var kd = KeyDataBi.init();
    try kd.genKeys(.{0x11} ** hash_algo.digest_length, .{0x22} ** kex_algo.shared_length, .{0x33} ** hash_algo.digest_length);
    // fill with non-zero data
    @memset(&kd.c2s.iv, 0xAA);
    @memset(&kd.c2s.key, 0xBB);
    @memset(&kd.c2s.mackey, 0xCC);
    @memset(&kd.s2c.iv, 0xDD);
    @memset(&kd.s2c.key, 0xEE);
    @memset(&kd.s2c.mackey, 0xFF);

    kd.clear();

    const zero_iv: [MaxIVLen]u8 = .{0} ** MaxIVLen;
    const zero_key: [MaxKeyLen]u8 = .{0} ** MaxKeyLen;
    try std.testing.expectEqualSlices(u8, &zero_iv, &kd.c2s.iv);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.c2s.key);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.c2s.mackey);
    try std.testing.expectEqualSlices(u8, &zero_iv, &kd.s2c.iv);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.s2c.key);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.s2c.mackey);
    for (std.mem.asBytes(&kd.c2s.aesctr)) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (std.mem.asBytes(&kd.s2c.aesctr)) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "RFC 4253 key derivation known-answer values" {
    var kd = KeyDataBi.init();
    defer kd.clear();
    try kd.genKeys(
        .{0x11} ** hash_algo.digest_length,
        .{0x22} ** kex_algo.shared_length,
        .{0x33} ** hash_algo.digest_length,
    );

    try std.testing.expectEqualStrings(
        "8441e455d5c7994f454d015def5da3f7b37f39b3",
        &std.fmt.bytesToHex(kd.c2s.iv, .lower),
    );
    try std.testing.expectEqualStrings(
        "59a323f617d854218c353b19836fb3822e88f2dc",
        &std.fmt.bytesToHex(kd.s2c.iv, .lower),
    );
    try std.testing.expectEqualStrings(
        "6c576d8021225f6a850479e89de9955a0b1dd72606a7a5bdc78644bb8454ff3e3581aaca0eb48ad49832316f26a2b0e58e6fb4234db5f755c91de7908dcd5159",
        &std.fmt.bytesToHex(kd.c2s.key, .lower),
    );
    try std.testing.expectEqualStrings(
        "30bb139eea959f6f80edd3e7e201d9de7cf84e6531e1c0e319a0bcff6f85a7cefddc9a01e81335bec5301f1524c127024abbb1175440d33dffa42bb011616cc3",
        &std.fmt.bytesToHex(kd.s2c.key, .lower),
    );
    try std.testing.expectEqualStrings(
        "891de80b5b0094a754825522d91f677ec5334e35ce41685e6e45a6a95389491b3430564ee9bb2e70404a980d0363d582fc3c617050deaaeb207c295cbe126f13",
        &std.fmt.bytesToHex(kd.c2s.mackey, .lower),
    );
    try std.testing.expectEqualStrings(
        "9bf2dcd1ba7dd872b42c633fe3e670e4e2f6ee706b3590f572641da35eee5de49fb889edccb61c0e8b243a1a1437dd7b70af415834c0600c12c0f04463d90757",
        &std.fmt.bytesToHex(kd.s2c.mackey, .lower),
    );
}

test "RFC 4231 HMAC-SHA-256 known-answer vector" {
    var actual: [mac_algo.mac_length]u8 = undefined;
    var hmac = mac_algo.init(&(.{0x0b} ** 20));
    hmac.update("Hi There");
    hmac.final(&actual);
    try std.testing.expectEqualStrings(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        &std.fmt.bytesToHex(actual, .lower),
    );
}

test "NIST SP 800-38A AES-256-CTR known-answer vector" {
    const key = [_]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    const iv = [_]u8{
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    const plaintext = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const expected = [_]u8{
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
        0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
        0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
        0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
        0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
    };

    var aes = AesCtrT.init(iv, key);
    defer aes.clear();
    var actual: [plaintext.len]u8 = undefined;
    try aes.encrypt(&plaintext, &actual);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "encrypted wrap capacity error does not expose plaintext" {
    var prng = std.Random.DefaultPrng.init(42);
    var rand = prng.random();
    var keys = KeyDataUni{ .seq = 0 };
    defer keys.clear();
    var iobuf: [AesCtrT.block_size * 2]u8 = .{0xA5} ** (AesCtrT.block_size * 2);

    try std.testing.expectError(IoError.tooBig, wrapPayload(&rand, true, &keys, "secret payload", &iobuf));
    try std.testing.expectEqualSlices(u8, &(.{0xA5} ** iobuf.len), &iobuf);
}
