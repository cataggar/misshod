const std = @import("std");
const Sshz = @import("sshz.zig");
const Protocol = @import("protocol.zig");
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferReader = @import("buffer.zig").BufferReader;
const zlib = @cImport({
    @cInclude("zlib.h");
});

const Open = enum { session, direct, forwarded, agent };
const Ordering = enum { receive_first, transmit_first, partial_header, partial_body, header_before_open, body_before_open };
const repeated_data = "A" ** 56;

fn Fixture(comptime opening: Open) type {
    const client = opening == .session or opening == .direct;
    const Endpoint = if (client) Sshz.SshzClient else Sshz.SshzServer;
    return struct {
        endpoint: Endpoint,
        peer_keys: Protocol.KeyDataBi = Protocol.KeyDataBi.init(),
        compressor: Protocol.CompressionState = .{ .algorithm = .ZlibOpenSsh },
        random: std.Random,
        channel: u32,
        delivered: usize = 0,
        wire: [Protocol.MaxSSHPacket]u8 = undefined,
        compressed: [Protocol.MaxPayload]u8 = undefined,
        output: [Protocol.MaxSSHPacket]u8 = undefined,
        output_len: usize = 0,

        const Self = @This();

        fn init(self: *Self, random: std.Random) !void {
            self.* = .{
                .endpoint = try Endpoint.init(
                    random,
                    if (client) "test" else @import("privkey.zig").testkey_valid,
                    std.testing.allocator,
                ),
                .random = random,
                .channel = undefined,
            };
            errdefer self.endpoint.deinit();
            if (!client) try self.endpoint.setServerChannelEventsEnabled(true);
            const session = &self.endpoint.session;
            const hash = [_]u8{0x31} ** Protocol.hash_algo.digest_length;
            const secret = [_]u8{0x42} ** Protocol.kex_algo.shared_length;
            const session_id = [_]u8{0x53} ** Protocol.hash_algo.digest_length;
            try session.keydata.genKeys(hash, secret, session_id);
            try self.peer_keys.genKeys(hash, secret, session_id);
            try session.keydata.c2s.activateEpoch(0, null);
            try session.keydata.s2c.activateEpoch(0, null);
            try session.setPeerProtocolVersion("SSH-2.0-receive_test");
            session.encrypted = true;
            session.inbound_encrypted = true;
            session.user_authenticated = true;
            session.session_id = session_id;
            session.session_id_established = true;
            session.setSessionState(.ChannelActive);
            session.setIoSessionState(.ReadPktHdr);
            if (client) session.auto_session_enabled = false;
            const chan = session.channel_table.allocChannel(42, 32768, 32768).?;
            chan.state = .DataRx;
            self.channel = chan.local_id;
            self.inKeys().compression.algorithm = .ZlibOpenSsh;
            try self.inKeys().compression.activateInflate();
            try self.compressor.activateDeflate();
        }

        fn deinit(self: *Self) void {
            self.compressor.deinit();
            self.peer_keys.clear();
            self.endpoint.deinit();
        }

        fn inKeys(self: *Self) *Protocol.KeyDataUni {
            return if (client) &self.endpoint.session.keydata.s2c else &self.endpoint.session.keydata.c2s;
        }

        fn peerOutKeys(self: *Self) *Protocol.KeyDataUni {
            return if (client) &self.peer_keys.s2c else &self.peer_keys.c2s;
        }

        fn packet(self: *Self, payload: []const u8) ![]const u8 {
            if (!self.compressor.active)
                return Protocol.wrapPayload(&self.random, true, self.peerOutKeys(), payload, &self.wire);
            // RFC 4253 permits partial flushes. Use the production framer,
            // cipher and MAC on the peer's already-compressed payload.
            const stream = &self.compressor.deflate_stream;
            stream.next_in = @ptrCast(@constCast(payload.ptr));
            stream.avail_in = @intCast(payload.len);
            stream.next_out = &self.compressed;
            stream.avail_out = self.compressed.len;
            try std.testing.expectEqual(zlib.Z_OK, zlib.deflate(@ptrCast(stream), zlib.Z_PARTIAL_FLUSH));
            try std.testing.expectEqual(@as(c_uint, 0), stream.avail_in);
            try std.testing.expect(stream.avail_out != 0);
            return Protocol.wrapPayload(
                &self.random,
                true,
                self.peerOutKeys(),
                self.compressed[0 .. self.compressed.len - stream.avail_out],
                &self.wire,
            );
        }

        fn dataPacket(self: *Self, data: []const u8) ![]const u8 {
            var payload: [256]u8 = undefined;
            var writer = BufferWriter.init(&payload, 0);
            try writer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
            try writer.writeU32(self.channel);
            try writer.writeU32LenString(data);
            return self.packet(writer.active());
        }

        fn feed(self: *Self, bytes: []const u8) !void {
            var offset: usize = 0;
            while (offset < bytes.len) {
                const ready = try self.endpoint.getNextEvent();
                const n = switch (ready) {
                    .ReadyToConsume => |n| n,
                    .ReadyToConsumeAndProduce => |both| both.consume,
                    else => return error.TestUnexpectedResult,
                };
                const count = @min(n, bytes.len - offset);
                try std.testing.expect(count != 0);
                try self.endpoint.write(bytes[offset..][0..count]);
                offset += count;
            }
        }

        fn takeData(self: *Self, expected: []const u8) !bool {
            switch (try self.endpoint.getNextEvent()) {
                .Event => |event| {
                    switch (event) {
                        .RxData => |data| {
                            try std.testing.expectEqual(self.channel, data.channel);
                            try std.testing.expectEqualStrings(expected, data.data);
                            self.delivered += 1;
                        },
                        else => return error.TestUnexpectedResult,
                    }
                    try self.endpoint.clearEvent(event);
                    return true;
                },
                .ReadyToConsume => return false,
                else => return error.TestUnexpectedResult,
            }
        }

        fn warmup(self: *Self) !void {
            for (0..4) |_| {
                try self.feed(try self.dataPacket(repeated_data));
                try std.testing.expect(try self.takeData(repeated_data));
            }
        }

        fn open(self: *Self) !u32 {
            return switch (opening) {
                .session => self.endpoint.openSessionChannel(),
                .direct => self.endpoint.openDirectTcpipChannel("example.test", 80, "127.0.0.1", 1234),
                .forwarded => self.endpoint.openForwardedTcpipChannel("127.0.0.1", 8080, "127.0.0.1", 1234),
                .agent => self.endpoint.openAgentChannel(),
            };
        }

        fn drain(self: *Self, max_bytes: usize) !usize {
            const ready = try self.endpoint.getNextEvent();
            const pending = switch (ready) {
                .ReadyToProduce => |n| n,
                .ReadyToConsumeAndProduce => |both| both.produce,
                else => return error.TestUnexpectedResult,
            };
            const bytes = try self.endpoint.peek(@min(pending, max_bytes));
            const n = bytes.len;
            @memcpy(self.output[self.output_len..][0..n], bytes);
            self.output_len += n;
            try self.endpoint.consumed(n);
            return n;
        }

        fn readOutput(self: *Self) !BufferReader {
            const keys = if (client) &self.peer_keys.c2s else &self.peer_keys.s2c;
            const encrypted_len = self.output_len - Protocol.mac_algo.key_length;
            var plaintext: [Protocol.MaxSSHPacket]u8 = undefined;
            try keys.aesctr.encrypt(self.output[0..encrypted_len], plaintext[0..encrypted_len]);
            var mac: [Protocol.mac_algo.key_length]u8 = undefined;
            var hasher = Protocol.mac_algo.init(keys.mackey[0..Protocol.mac_algo.key_length]);
            const seq = std.mem.nativeTo(u32, keys.seq, .big);
            hasher.update(std.mem.asBytes(&seq));
            hasher.update(plaintext[0..encrypted_len]);
            hasher.final(&mac);
            try std.testing.expectEqualSlices(u8, &mac, self.output[encrypted_len..self.output_len]);
            keys.seq += 1;
            const payload_end = encrypted_len - plaintext[4];
            @memcpy(self.output[0..encrypted_len], plaintext[0..encrypted_len]);
            self.output_len = 0;
            return BufferReader.init(self.output[Protocol.sizeof_PktHdr..payload_end]);
        }

        fn checkOpen(self: *Self, channel_id: u32) !void {
            var reader = try self.readOutput();
            try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try reader.readU8());
            try std.testing.expectEqualStrings(switch (opening) {
                .session => "session",
                .direct => "direct-tcpip",
                .forwarded => "forwarded-tcpip",
                .agent => Protocol.channel_type_auth_agent_openssh,
            }, try reader.readU32LenString());
            try std.testing.expectEqual(channel_id, try reader.readU32());
        }

        fn reply(self: *Self, channel_id: u32, accepted: bool) !void {
            var payload: [128]u8 = undefined;
            var writer = BufferWriter.init(&payload, 0);
            try writer.writeU8(@intFromEnum(if (accepted)
                Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            else
                Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
            try writer.writeU32(channel_id);
            if (accepted) {
                try writer.writeU32(99);
                try writer.writeU32(32768);
                try writer.writeU32(32768);
            } else {
                try writer.writeU32(1);
                try writer.writeU32LenString("declined");
                try writer.writeU32LenString("");
            }
            try self.feed(try self.packet(writer.active()));
            const ready = try self.endpoint.getNextEvent();
            try std.testing.expect(ready == .Event);
            const event = ready.Event;
            if (opening == .agent) {
                if (accepted) {
                    try std.testing.expect(event == .AgentChannelOpen);
                    try std.testing.expectEqual(channel_id, event.AgentChannelOpen);
                } else {
                    try std.testing.expect(event == .AgentChannelClosed);
                    try std.testing.expectEqual(channel_id, event.AgentChannelClosed);
                }
            } else if (accepted) {
                try std.testing.expect(event == .ChannelOpened);
                try std.testing.expectEqual(channel_id, event.ChannelOpened);
            } else {
                try std.testing.expect(event == .ChannelOpenFailure);
                try std.testing.expectEqual(channel_id, event.ChannelOpenFailure.channel);
                try std.testing.expectEqualStrings("declined", event.ChannelOpenFailure.description);
            }
            try self.endpoint.clearEvent(event);
            if (accepted) {
                const chan = self.endpoint.session.channel_table.findByLocalId(channel_id).?;
                try std.testing.expect(chan.remote_id_known);
                try std.testing.expectEqual(@as(u32, 99), chan.remote_id);
            } else {
                try std.testing.expect(self.endpoint.session.channel_table.findByLocalId(channel_id) == null);
            }
        }
    };
}

fn overlap(comptime opening: Open, ordering: Ordering, compressed: bool) !void {
    var prng = std.Random.DefaultPrng.init(913);
    var fixture: Fixture(opening) = undefined;
    try fixture.init(prng.random());
    defer fixture.deinit();
    if (!compressed) {
        fixture.compressor.active = false;
        fixture.inKeys().compression.active = false;
    }
    try fixture.warmup();
    const packet = try fixture.dataPacket(repeated_data);
    if (compressed) {
        try std.testing.expectEqual(Protocol.AesCtrT.block_size + Protocol.mac_algo.key_length, packet.len);
    } else {
        try std.testing.expect(packet.len > Protocol.AesCtrT.block_size + Protocol.mac_algo.key_length);
    }

    var offset: usize = switch (ordering) {
        .header_before_open => 7,
        .body_before_open => Protocol.AesCtrT.block_size + 3,
        else => 0,
    };
    try fixture.feed(packet[0..offset]);
    const opened = try fixture.open();
    _ = try fixture.drain(1);
    const before_drain = switch (ordering) {
        .receive_first, .header_before_open, .body_before_open => packet.len,
        .transmit_first => offset,
        .partial_header => 7,
        .partial_body => Protocol.AesCtrT.block_size + 3,
    };
    try fixture.feed(packet[offset..before_drain]);
    offset = before_drain;
    if (offset == packet.len)
        try std.testing.expect(fixture.endpoint.session.ioSessionState == .ReadPktCompletion);
    const receive_state = fixture.endpoint.session.ioSessionState;
    _ = try fixture.drain(0);
    try std.testing.expect(std.meta.eql(receive_state, fixture.endpoint.session.ioSessionState));
    try std.testing.expectEqual(@as(usize, 1), fixture.endpoint.wr_off);
    _ = try fixture.drain(Protocol.MaxSSHPacket);
    try fixture.checkOpen(opened);
    try fixture.feed(packet[offset..]);
    // Continue even if this packet was lost, so the assertion below also
    // proves that later authenticated packets and inflate calls succeeded.
    _ = try fixture.takeData(repeated_data);
    for (0..2) |_| {
        try fixture.feed(try fixture.dataPacket(repeated_data));
        try std.testing.expect(try fixture.takeData(repeated_data));
    }
    try fixture.reply(opened, true);
    try fixture.feed(try fixture.dataPacket("distinct subsequent data"));
    try std.testing.expect(try fixture.takeData("distinct subsequent data"));
    try std.testing.expect(!try fixture.takeData(""));
    try std.testing.expectEqual(@as(usize, 8), fixture.delivered);
    try std.testing.expectEqual(@as(u32, 9), fixture.inKeys().seq);
    try std.testing.expectEqual(@as(u64, 9), fixture.inKeys().encrypted_packets);
}

test "client session OPEN preserves authenticated compressed receive completion" {
    try overlap(.session, .receive_first, true);
}

test "client direct-tcpip OPEN preserves authenticated compressed receive completion" {
    try overlap(.direct, .receive_first, true);
}

test "server forwarded-tcpip OPEN preserves authenticated compressed receive completion" {
    try overlap(.forwarded, .receive_first, true);
}

test "channel OPEN preserves partial header body and write-first orderings" {
    inline for (.{ Open.session, Open.direct, Open.forwarded, Open.agent }) |opening| {
        for ([_]Ordering{ .transmit_first, .partial_header, .partial_body, .header_before_open, .body_before_open }) |ordering| {
            try overlap(opening, ordering, true);
        }
    }
}

test "channel OPEN preserves multiblock uncompressed receive orderings" {
    inline for (.{ Open.session, Open.direct, Open.forwarded, Open.agent }) |opening| {
        for (std.enums.values(Ordering)) |ordering| {
            try overlap(opening, ordering, false);
        }
    }
}

test "channel OPEN overlap rejects an invalid MAC instead of skipping it" {
    inline for (.{ Open.session, Open.direct, Open.forwarded, Open.agent }) |opening| {
        var prng = std.Random.DefaultPrng.init(914);
        var fixture: Fixture(opening) = undefined;
        try fixture.init(prng.random());
        defer fixture.deinit();
        try fixture.warmup();
        const packet = try fixture.dataPacket(repeated_data);
        fixture.wire[packet.len - 1] ^= 1;
        _ = try fixture.open();
        _ = try fixture.drain(1);
        try fixture.feed(packet);
        try std.testing.expect(fixture.endpoint.session.ioSessionState == .ReadPktCompletion);
        try std.testing.expectError(Sshz.IoError.InvalidMac, fixture.drain(Protocol.MaxSSHPacket));
        try std.testing.expect(fixture.endpoint.terminated);
        try std.testing.expectError(Sshz.IoError.SessionTerminated, fixture.endpoint.getNextEvent());
        try std.testing.expectEqual(@as(usize, 4), fixture.delivered);
    }
}

test "nonoverlapped channel OPEN confirmation failure and next open progress" {
    inline for (.{ Open.session, Open.direct, Open.forwarded, Open.agent }) |opening| {
        var prng = std.Random.DefaultPrng.init(915);
        var fixture: Fixture(opening) = undefined;
        try fixture.init(prng.random());
        defer fixture.deinit();
        for ([_]bool{ true, false, true }) |accepted| {
            fixture.output_len = 0;
            const channel_id = try fixture.open();
            _ = try fixture.drain(Protocol.MaxSSHPacket);
            try fixture.checkOpen(channel_id);
            try fixture.reply(channel_id, accepted);
            try fixture.feed(try fixture.dataPacket(repeated_data));
            try std.testing.expect(try fixture.takeData(repeated_data));
        }
    }
}

test "server agent OPEN retains a partial incoming packet" {
    try overlap(.agent, .body_before_open, true);
}

test "channel OPEN completion processes received EOF and CLOSE before queued controls" {
    inline for (.{ Open.session, Open.direct, Open.forwarded, Open.agent }) |opening| {
        var prng = std.Random.DefaultPrng.init(916);
        var fixture: Fixture(opening) = undefined;
        try fixture.init(prng.random());
        defer fixture.deinit();
        try fixture.warmup();
        for ([_]Protocol.MsgId{ .SSH_MSG_CHANNEL_EOF, .SSH_MSG_CHANNEL_CLOSE }) |control| {
            const channel_id = try fixture.open();
            _ = try fixture.drain(1);
            if (control == .SSH_MSG_CHANNEL_CLOSE)
                try fixture.endpoint.sendChannelEof(fixture.channel);
            var payload: [5]u8 = undefined;
            var writer = BufferWriter.init(&payload, 0);
            try writer.writeU8(@intFromEnum(control));
            try writer.writeU32(fixture.channel);
            try fixture.feed(try fixture.packet(writer.active()));
            _ = try fixture.drain(Protocol.MaxSSHPacket);
            try fixture.checkOpen(channel_id);
            const chan = fixture.endpoint.session.channel_table.findByLocalId(fixture.channel).?;
            if (control == .SSH_MSG_CHANNEL_EOF) {
                try std.testing.expect(chan.eof_received);
                const ready = try fixture.endpoint.getNextEvent();
                try std.testing.expect(ready == .Event);
                try std.testing.expectEqual(fixture.channel, ready.Event.ChannelEof);
                try fixture.endpoint.clearEvent(ready.Event);
                try fixture.feed(try fixture.packet(writer.active()));
                try std.testing.expect(!try fixture.takeData(""));
                try fixture.feed(try fixture.dataPacket("ignored after EOF"));
                try std.testing.expect(!try fixture.takeData(""));
            } else {
                try std.testing.expect(chan.close_received);
                try std.testing.expect(!chan.eof_sent);
                try std.testing.expectEqual(.Close, chan.control_in_flight.?);
                _ = try fixture.drain(Protocol.MaxSSHPacket);
                var reply = try fixture.readOutput();
                try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE), try reply.readU8());
                try std.testing.expectEqual(@as(u32, 42), try reply.readU32());
                if (opening == .session or opening == .direct) {
                    const ready = try fixture.endpoint.getNextEvent();
                    try std.testing.expect(ready == .Event);
                    try std.testing.expectEqual(fixture.channel, ready.Event.ChannelClosed);
                    try fixture.endpoint.clearEvent(ready.Event);
                }
                try std.testing.expect(fixture.endpoint.session.channel_table.findByLocalId(fixture.channel) == null);
            }
            try fixture.reply(channel_id, true);
            try std.testing.expect(!try fixture.takeData(""));
        }
        try std.testing.expectEqual(@as(usize, 4), fixture.delivered);
        try std.testing.expectEqual(@as(u64, 10), fixture.inKeys().encrypted_packets);
    }
}

test "local rekey waits for OPEN-overlapped packet authentication and delivery" {
    inline for (.{ Open.session, Open.direct, Open.forwarded, Open.agent }) |opening| {
        var prng = std.Random.DefaultPrng.init(917);
        var fixture: Fixture(opening) = undefined;
        try fixture.init(prng.random());
        defer fixture.deinit();
        try fixture.warmup();
        const opened = try fixture.open();
        _ = try fixture.drain(1);
        try fixture.feed(try fixture.dataPacket(repeated_data));
        fixture.endpoint.limits.key_lifetime.rekey_after_encrypted_packets = 1;
        _ = try fixture.drain(Protocol.MaxSSHPacket);
        try fixture.checkOpen(opened);
        try std.testing.expect(!fixture.endpoint.session.is_rekeying);
        try std.testing.expect(fixture.endpoint.local_rekey_pending);
        try std.testing.expectEqual(@as(u64, 5), fixture.inKeys().encrypted_packets);
        const ready = try fixture.endpoint.getNextEvent();
        try std.testing.expect(ready == .Event);
        try std.testing.expectEqualStrings(repeated_data, ready.Event.RxData.data);
        try fixture.endpoint.clearEvent(ready.Event);
        try std.testing.expect(fixture.endpoint.session.is_rekeying);
        try std.testing.expectEqual(.OpenSent, fixture.endpoint.session.channel_table.findByLocalId(opened).?.state);
        _ = try fixture.drain(Protocol.MaxSSHPacket);
        var kex = try fixture.readOutput();
        try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT), try kex.readU8());
        try std.testing.expectEqual(@as(u64, 5), fixture.inKeys().encrypted_packets);
    }
}

test "server agent OPEN cannot replace an active write or borrowing event" {
    var prng = std.Random.DefaultPrng.init(918);
    var fixture: Fixture(.agent) = undefined;
    try fixture.init(prng.random());
    defer fixture.deinit();
    try fixture.warmup();
    const opened = try fixture.open();
    _ = try fixture.drain(1);
    const write_state = fixture.endpoint.iostate_wr;
    const channel_count = fixture.endpoint.session.channel_table.activeCount();
    try std.testing.expectError(Sshz.IoError.cannotAcceptWrite, fixture.open());
    try std.testing.expectEqual(channel_count, fixture.endpoint.session.channel_table.activeCount());
    try std.testing.expect(std.meta.eql(write_state, fixture.endpoint.iostate_wr));
    try std.testing.expectEqual(@as(usize, 1), fixture.endpoint.wr_off);
    try fixture.feed(try fixture.dataPacket(repeated_data));
    _ = try fixture.drain(Protocol.MaxSSHPacket);
    try fixture.checkOpen(opened);
    try std.testing.expectError(Sshz.IoError.cannotAcceptWrite, fixture.open());
    try std.testing.expect(try fixture.takeData(repeated_data));
    try fixture.reply(opened, true);
}

test "peer rekey received during OPEN retains serialized KEX write continuations" {
    inline for (.{ Open.session, Open.direct, Open.forwarded, Open.agent }) |opening| {
        var prng = std.Random.DefaultPrng.init(919);
        var fixture: Fixture(opening) = undefined;
        try fixture.init(prng.random());
        defer fixture.deinit();
        try fixture.warmup();
        const opened = try fixture.open();
        _ = try fixture.drain(1);

        var payload: [2048]u8 = undefined;
        var writer = BufferWriter.init(&payload, 0);
        try writer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
        try writer.writeBytes(&(.{0} ** 16));
        const offers = Protocol.localAlgorithmOffers(@import("key.zig").client_hostkey_algorithms);
        inline for (std.meta.fields(Protocol.AlgorithmOffers)) |field| {
            try writer.writeU32LenString(@field(offers, field.name));
        }
        try writer.writeU32LenString("");
        try writer.writeU32LenString("");
        try writer.writeBoolean(false);
        try writer.writeU32(0);
        try fixture.feed(try fixture.packet(writer.active()));
        try std.testing.expect(!fixture.endpoint.session.is_rekeying);
        _ = try fixture.drain(Protocol.MaxSSHPacket);
        try fixture.checkOpen(opened);
        try std.testing.expect(fixture.endpoint.session.is_rekeying);
        try std.testing.expectEqual(@as(u64, 5), fixture.inKeys().encrypted_packets);
        _ = try fixture.drain(Protocol.MaxSSHPacket);
        var response = try fixture.readOutput();
        try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT), try response.readU8());
        if (opening == .session or opening == .direct) {
            _ = try fixture.drain(Protocol.MaxSSHPacket);
            response = try fixture.readOutput();
            try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT), try response.readU8());
        }
        try std.testing.expect(!try fixture.takeData(""));
        try std.testing.expectEqual(@as(u64, 5), fixture.inKeys().encrypted_packets);
        try std.testing.expectError(Sshz.IoError.NotReady, fixture.open());
        try std.testing.expectEqual(.OpenSent, fixture.endpoint.session.channel_table.findByLocalId(opened).?.state);
    }
}
