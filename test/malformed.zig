const std = @import("std");
const sshz = @import("sshz");

const max_steps = 64;
const max_input_bytes = 512;
const corpus_seed: u64 = 0x60_4d_41_4c_46_4f_52_4d;

const Operation = enum {
    identification,
    packet,
    encrypted_packet,
    mac,
    compression,
    string,
    mpint,
    ecdh_public_key,
    message,
    reader_skip,
    writer_init,
    writer_skip,
    writer_mpint,
    client_kexinit,
    client_packet,
    client_channel_data_wrong_state,
    client_channel_packet_too_large,
    client_channel_receive_window,
    client_channel_extended_truncated,
    client_channel_window_overflow,
    client_channel_close_disconnect,
};

const CorpusExpectedError = error{
    noEOLFound,
    UnexpectedResponse,
    notEnoughData,
    InvalidPacketSize,
    InvalidMac,
    ReaderOutOfDataErr,
    WriterOutOfDataErr,
    UnsupportedMessage,
    AlgorithmNegotiationFailed,
    ChannelPacketTooLarge,
    ReceiveWindowExceeded,
    WindowOverflow,
    InvalidChannelParameters,
};

const ExpectedError = enum {
    no_eol,
    unexpected_response,
    not_enough_data,
    invalid_packet_size,
    invalid_mac,
    reader_out_of_data,
    writer_out_of_data,
    unsupported_message,
    algorithm_negotiation_failed,
    channel_packet_too_large,
    receive_window_exceeded,
    window_overflow,
    invalid_channel_parameters,
    peer_disconnect,
    channel_disconnect,

    fn value(self: ExpectedError) CorpusExpectedError {
        return switch (self) {
            .no_eol => error.noEOLFound,
            .unexpected_response => error.UnexpectedResponse,
            .not_enough_data => error.notEnoughData,
            .invalid_packet_size => error.InvalidPacketSize,
            .invalid_mac => error.InvalidMac,
            .reader_out_of_data => error.ReaderOutOfDataErr,
            .writer_out_of_data => error.WriterOutOfDataErr,
            .unsupported_message => error.UnsupportedMessage,
            .algorithm_negotiation_failed => error.AlgorithmNegotiationFailed,
            .channel_packet_too_large => error.ChannelPacketTooLarge,
            .receive_window_exceeded => error.ReceiveWindowExceeded,
            .window_overflow => error.WindowOverflow,
            .invalid_channel_parameters => error.InvalidChannelParameters,
            .peer_disconnect, .channel_disconnect => unreachable,
        };
    }
};

const CorpusCase = struct {
    name: []const u8,
    operation: Operation,
    input: []const u8,
    expected: ExpectedError,
};

const oversized_identification = [_]u8{'A'} ** 256;
const valid_packet = [_]u8{
    0, 0, 0, 12, 10,
    2,
} ++ ([_]u8{0} ** 10);
const overlong_packet = valid_packet ++ [_]u8{0};
const truncated_mac_packet = valid_packet ++ ([_]u8{0} ** (sshz.TransportLimits.mac_len - 1));
const bad_block_packet = [_]u8{
    0, 0, 0, 8, 6,
    2,
} ++ ([_]u8{0} ** 6) ++ ([_]u8{0} ** sshz.TransportLimits.mac_len);
const corrupt_mac = ([_]u8{0} ** (sshz.TransportLimits.mac_len - 1)) ++ [_]u8{1};
const truncated_ecdh_key = [_]u8{0x42} ** (sshz.TransportLimits.ecdh_public_key_len - 1);
const ecdh_reply_trailing = [_]u8{
    31,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    sshz.TransportLimits.ecdh_public_key_len,
} ++ ([_]u8{0x42} ** sshz.TransportLimits.ecdh_public_key_len) ++ [_]u8{
    0,    0, 0, 0,
    0xff,
};
const channel_data_one_byte = [_]u8{
    94,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    'x',
};
const channel_data_five_bytes = [_]u8{
    94,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    5,
    '1',
    '2',
    '3',
    '4',
    '5',
};
const channel_data_four_bytes = [_]u8{
    94,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    4,
    '1',
    '2',
    '3',
    '4',
};
const channel_extended_truncated = [_]u8{
    95,
    0,
    0,
    0,
    0,
};
const channel_window_overflow = [_]u8{
    93,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    2,
};
const channel_open_zero_packet = [_]u8{
    91,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    0,
};
const peer_disconnect = [_]u8{
    1,
    0,
    0,
    0,
    2,
    0,
    0,
    0,
    3,
    'b',
    'y',
    'e',
    0,
    0,
    0,
    0,
};
const channel_close = [_]u8{
    97,
    0,
    0,
    0,
    0,
};

const corpus = [_]CorpusCase{
    .{ .name = "identification-empty", .operation = .identification, .input = "", .expected = .no_eol },
    .{ .name = "identification-short", .operation = .identification, .input = "SSH", .expected = .no_eol },
    .{ .name = "identification-oversized", .operation = .identification, .input = &oversized_identification, .expected = .no_eol },
    .{ .name = "identification-invalid-version", .operation = .identification, .input = "SSH-3.0-peer\n", .expected = .unexpected_response },
    .{ .name = "identification-invalid-comment", .operation = .identification, .input = "SSH-2.0-peer \x80\n", .expected = .unexpected_response },

    .{ .name = "packet-empty-header", .operation = .packet, .input = "", .expected = .not_enough_data },
    .{ .name = "packet-short-header", .operation = .packet, .input = &.{ 0, 0, 0, 12 }, .expected = .not_enough_data },
    .{ .name = "packet-zero-length", .operation = .packet, .input = &.{ 0, 0, 0, 0, 4 }, .expected = .invalid_packet_size },
    .{ .name = "packet-oversized-length", .operation = .packet, .input = &.{ 0xff, 0xff, 0xff, 0xff, 4 }, .expected = .invalid_packet_size },
    .{ .name = "padding-zero", .operation = .packet, .input = &.{ 0, 0, 0, 2, 0 }, .expected = .invalid_packet_size },
    .{ .name = "padding-below-minimum", .operation = .packet, .input = &.{ 0, 0, 0, 5, 3 }, .expected = .invalid_packet_size },
    .{ .name = "padding-minimum-with-short-length", .operation = .packet, .input = &.{ 0, 0, 0, 4, 4 }, .expected = .invalid_packet_size },
    .{ .name = "padding-maximum-with-short-length", .operation = .packet, .input = &.{ 0, 0, 0, 0xff, 0xff }, .expected = .invalid_packet_size },
    .{ .name = "packet-truncated-body", .operation = .packet, .input = valid_packet[0 .. valid_packet.len - 1], .expected = .not_enough_data },
    .{ .name = "packet-overlong-body", .operation = .packet, .input = &overlong_packet, .expected = .invalid_packet_size },
    .{ .name = "packet-invalid-cipher-block-boundary", .operation = .encrypted_packet, .input = &bad_block_packet, .expected = .invalid_packet_size },
    .{ .name = "packet-truncated-mac", .operation = .encrypted_packet, .input = &truncated_mac_packet, .expected = .invalid_mac },
    .{ .name = "packet-corrupt-mac", .operation = .mac, .input = &corrupt_mac, .expected = .invalid_mac },
    .{ .name = "compression-corrupt-stream", .operation = .compression, .input = "not a zlib stream", .expected = .invalid_packet_size },

    .{ .name = "string-short-length", .operation = .string, .input = &.{ 0, 0, 0 }, .expected = .reader_out_of_data },
    .{ .name = "string-oversized-length", .operation = .string, .input = &.{ 0xff, 0xff, 0xff, 0xff }, .expected = .reader_out_of_data },
    .{ .name = "string-truncated-body", .operation = .string, .input = &.{ 0, 0, 0, 3, 'a', 'b' }, .expected = .reader_out_of_data },
    .{ .name = "mpint-short-length", .operation = .mpint, .input = &.{ 0, 0 }, .expected = .reader_out_of_data },
    .{ .name = "mpint-oversized-length", .operation = .mpint, .input = &.{ 0xff, 0xff, 0xff, 0xff }, .expected = .reader_out_of_data },
    .{ .name = "mpint-truncated-body", .operation = .mpint, .input = &.{ 0, 0, 0, 2, 0x7f }, .expected = .reader_out_of_data },
    .{ .name = "regression-short-ecdh-seed", .operation = .ecdh_public_key, .input = &truncated_ecdh_key, .expected = .unexpected_response },

    .{ .name = "message-missing-id", .operation = .message, .input = "", .expected = .reader_out_of_data },
    .{ .name = "message-unknown-zero", .operation = .message, .input = &.{0}, .expected = .unsupported_message },
    .{ .name = "message-unknown-maximum", .operation = .message, .input = &.{0xff}, .expected = .unsupported_message },
    .{ .name = "reader-overflowing-skip", .operation = .reader_skip, .input = &.{0}, .expected = .reader_out_of_data },
    .{ .name = "writer-oversized-reservation", .operation = .writer_init, .input = "", .expected = .writer_out_of_data },
    .{ .name = "writer-overflowing-skip", .operation = .writer_skip, .input = "", .expected = .writer_out_of_data },
    .{ .name = "writer-padded-mpint-boundary", .operation = .writer_mpint, .input = &.{0x80}, .expected = .writer_out_of_data },

    .{ .name = "kexinit-truncated-cookie", .operation = .client_packet, .input = &.{20}, .expected = .reader_out_of_data },
    .{ .name = "kexinit-invalid-empty-name", .operation = .client_kexinit, .input = "curve25519-sha256,,invalid", .expected = .algorithm_negotiation_failed },
    .{ .name = "kexinit-no-common-algorithm", .operation = .client_kexinit, .input = "unsupported-kex", .expected = .algorithm_negotiation_failed },
    .{ .name = "ecdh-reply-before-ecdh-state", .operation = .client_packet, .input = &.{31}, .expected = .unexpected_response },
    .{ .name = "ecdh-reply-trailing-data", .operation = .client_packet, .input = &ecdh_reply_trailing, .expected = .unexpected_response },
    .{ .name = "newkeys-before-negotiation", .operation = .client_packet, .input = &.{21}, .expected = .unexpected_response },

    .{ .name = "auth-service-accept-before-request", .operation = .client_packet, .input = &.{6}, .expected = .unexpected_response },
    .{ .name = "auth-success-without-attempt", .operation = .client_packet, .input = &.{52}, .expected = .unexpected_response },
    .{ .name = "auth-failure-truncated-methods", .operation = .client_packet, .input = &.{ 51, 0, 0, 0, 4, 'p' }, .expected = .reader_out_of_data },
    .{ .name = "auth-banner-missing-language", .operation = .client_packet, .input = &.{ 53, 0, 0, 0, 3, 'b', 'a', 'd' }, .expected = .reader_out_of_data },
    .{ .name = "auth-info-request-missing-prompt", .operation = .client_packet, .input = &.{
        60,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    }, .expected = .reader_out_of_data },

    .{ .name = "channel-data-truncated-recipient", .operation = .client_packet, .input = &.{ 94, 0, 0 }, .expected = .reader_out_of_data },
    .{ .name = "channel-data-in-open-state", .operation = .client_channel_data_wrong_state, .input = &channel_data_one_byte, .expected = .unexpected_response },
    .{ .name = "channel-data-over-packet-limit", .operation = .client_channel_packet_too_large, .input = &channel_data_five_bytes, .expected = .channel_packet_too_large },
    .{ .name = "channel-data-over-window", .operation = .client_channel_receive_window, .input = &channel_data_four_bytes, .expected = .receive_window_exceeded },
    .{ .name = "channel-extended-data-missing-type", .operation = .client_channel_extended_truncated, .input = &channel_extended_truncated, .expected = .reader_out_of_data },
    .{ .name = "channel-window-adjust-overflow", .operation = .client_channel_window_overflow, .input = &channel_window_overflow, .expected = .window_overflow },
    .{ .name = "channel-open-zero-max-packet", .operation = .client_packet, .input = &channel_open_zero_packet, .expected = .invalid_channel_parameters },
    .{ .name = "global-success-without-request", .operation = .client_packet, .input = &.{81}, .expected = .unexpected_response },
    .{ .name = "disconnect-truncated-reason", .operation = .client_packet, .input = &.{ 1, 0, 0 }, .expected = .reader_out_of_data },
    .{ .name = "peer-disconnect-explicit-outcome", .operation = .client_packet, .input = &peer_disconnect, .expected = .peer_disconnect },
    .{ .name = "channel-close-explicit-disconnect", .operation = .client_channel_close_disconnect, .input = &channel_close, .expected = .channel_disconnect },
};

fn buildUnencryptedPacket(buf: []u8, payload: []const u8, seed: u64) !usize {
    const padding_len: u8 = 8;
    const packet_len = 4 + payload.len + 1 + padding_len;
    if (packet_len > buf.len or packet_len > max_input_bytes) return error.InvalidPacketSize;

    std.mem.writeInt(u32, buf[0..4], @intCast(payload.len + 1 + padding_len), .big);
    buf[4] = padding_len;
    @memcpy(buf[5 .. 5 + payload.len], payload);
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(buf[5 + payload.len .. packet_len]);
    return packet_len;
}

fn expectClientOutcome(
    case: CorpusCase,
    client: *sshz.SshzClient,
    result: sshz.SshzError!void,
) !void {
    switch (case.expected) {
        .peer_disconnect => {
            try result;
            const next = try client.getNextEvent();
            switch (next) {
                .Event => |event| switch (event) {
                    .EndSession => |reason| switch (reason) {
                        .ServerDisconnect => |disconnect| {
                            try std.testing.expectEqual(@as(u32, 2), disconnect.code);
                            try std.testing.expectEqualStrings("bye", disconnect.description);
                        },
                        else => return error.UnexpectedResponse,
                    },
                    else => return error.UnexpectedResponse,
                },
                else => return error.UnexpectedResponse,
            }
        },
        .channel_disconnect => {
            try result;
            const next = try client.getNextEvent();
            switch (next) {
                .Event => |event| switch (event) {
                    .ChannelClosed => |channel_id| try std.testing.expectEqual(@as(u32, 0), channel_id),
                    else => return error.UnexpectedResponse,
                },
                else => return error.UnexpectedResponse,
            }
            try client.clearEvent(.{ .ChannelClosed = 0 });
            const terminal = try client.getNextEvent();
            switch (terminal) {
                .Event => |event| switch (event) {
                    .EndSession => |reason| switch (reason) {
                        .Disconnect => {},
                        else => return error.UnexpectedResponse,
                    },
                    else => return error.UnexpectedResponse,
                },
                else => return error.UnexpectedResponse,
            }
        },
        else => try std.testing.expectError(case.expected.value(), result),
    }
}

fn runClientCase(case: CorpusCase, case_index: usize) !void {
    const seed = corpus_seed +% case_index;
    var prng = std.Random.DefaultPrng.init(seed);
    var client = try sshz.SshzClient.init(prng.random(), "malformed-corpus", std.testing.allocator);
    defer client.deinit();

    var generated_payload: [max_input_bytes]u8 = undefined;
    var payload = case.input;
    switch (case.operation) {
        .client_kexinit => {
            var writer = sshz.BufferWriter.init(&generated_payload, 0);
            try writer.writeU8(20);
            try writer.writeBytes(&([_]u8{0} ** 16));
            try writer.writeU32LenString(case.input);
            try writer.writeU32LenString("ssh-ed25519");
            inline for (0..2) |_| try writer.writeU32LenString("aes256-ctr");
            inline for (0..2) |_| try writer.writeU32LenString("hmac-sha2-256");
            inline for (0..2) |_| try writer.writeU32LenString("none");
            inline for (0..2) |_| try writer.writeU32LenString("");
            try writer.writeBoolean(false);
            try writer.writeU32(0);
            payload = writer.active();
            client.session.kex_hash_order = .I_C;
            client.session.setSessionState(.KexInitRead);
        },
        .client_packet => switch (case.input[0]) {
            20 => {
                client.session.kex_hash_order = .I_C;
                client.session.setSessionState(.KexInitRead);
            },
            31 => if (case.input.len > 1) client.session.setSessionState(.EcdhReply),
            // Userauth replies are gated on the authentication phase, so park the
            // session there to exercise the parser rather than the phase gate.
            51, 52, 60 => client.session.setSessionState(.AuthMethodQueued),
            // Connection-protocol messages are gated on authentication, so put the
            // session past userauth to exercise the parser rather than the gate.
            80...127 => {
                client.session.user_authenticated = true;
            },
            else => {},
        },
        .client_channel_data_wrong_state => {
            client.session.user_authenticated = true;
            _ = client.session.channel_table.allocChannel(1, 16, 16) orelse
                return error.UnexpectedResponse;
        },
        .client_channel_packet_too_large => {
            client.session.user_authenticated = true;
            const channel = client.session.channel_table.allocChannel(1, 16, 16) orelse
                return error.UnexpectedResponse;
            channel.state = .DataRx;
            channel.local_max_packet_size = 4;
        },
        .client_channel_receive_window => {
            client.session.user_authenticated = true;
            const channel = client.session.channel_table.allocChannel(1, 16, 16) orelse
                return error.UnexpectedResponse;
            channel.state = .DataRx;
            channel.local_window = 3;
        },
        .client_channel_extended_truncated => {
            client.session.user_authenticated = true;
            const channel = client.session.channel_table.allocChannel(1, 16, 16) orelse
                return error.UnexpectedResponse;
            channel.state = .DataRx;
        },
        .client_channel_window_overflow => {
            client.session.user_authenticated = true;
            const channel = client.session.channel_table.allocChannel(
                1,
                std.math.maxInt(u32) - 1,
                16,
            ) orelse return error.UnexpectedResponse;
            channel.state = .DataRx;
        },
        .client_channel_close_disconnect => {
            client.session.user_authenticated = true;
            const channel = client.session.channel_table.allocChannel(1, 16, 16) orelse
                return error.UnexpectedResponse;
            channel.state = .DataRx;
            channel.close_sent = true;
        },
        else => unreachable,
    }

    try std.testing.expect(payload.len <= max_input_bytes);
    const packet_len = try buildUnencryptedPacket(&client.iobuf_rd, payload, seed);
    try expectClientOutcome(
        case,
        &client,
        client.session.handlePacket(client.iobuf_rd[0..packet_len], &client),
    );
}

fn runCase(case: CorpusCase, case_index: usize) !void {
    switch (case.operation) {
        .identification => try std.testing.expectError(case.expected.value(), sshz.inspectIdentificationLine(case.input)),
        .packet => try std.testing.expectError(case.expected.value(), sshz.inspectPacket(case.input, false)),
        .encrypted_packet => try std.testing.expectError(case.expected.value(), sshz.inspectPacket(case.input, true)),
        .mac => {
            const calculated = [_]u8{0} ** sshz.TransportLimits.mac_len;
            try std.testing.expectError(case.expected.value(), sshz.verifyPacketMac(calculated, case.input));
        },
        .compression => {
            var state: sshz.CompressionState = .{ .algorithm = .ZlibOpenSsh };
            defer state.deinit();
            try state.activateInflate();
            var output: [sshz.TransportLimits.max_payload_len]u8 = undefined;
            try std.testing.expectError(case.expected.value(), state.decompressPayload(case.input, &output));
        },
        .string => {
            var reader = sshz.BufferReader.init(case.input);
            try std.testing.expectError(case.expected.value(), reader.readU32LenString());
        },
        .mpint => {
            var reader = sshz.BufferReader.init(case.input);
            try std.testing.expectError(case.expected.value(), reader.readMpint());
        },
        .ecdh_public_key => try std.testing.expectError(
            case.expected.value(),
            sshz.exerciseEcdhReplyPublicKey(case.input, std.testing.allocator),
        ),
        .message => try std.testing.expectError(case.expected.value(), sshz.inspectMessageFraming(case.input)),
        .reader_skip => {
            var reader = sshz.BufferReader.init(case.input);
            try std.testing.expectError(case.expected.value(), reader.skip(std.math.maxInt(usize)));
        },
        .writer_init => {
            var backing: [4]u8 = undefined;
            try std.testing.expectError(case.expected.value(), sshz.BufferWriter.initChecked(&backing, backing.len + 1));
        },
        .writer_skip => {
            var backing: [4]u8 = undefined;
            var writer = sshz.BufferWriter.init(&backing, 0);
            try std.testing.expectError(case.expected.value(), writer.skip(std.math.maxInt(usize)));
        },
        .writer_mpint => {
            var backing: [5]u8 = undefined;
            var writer = sshz.BufferWriter.init(&backing, 0);
            try std.testing.expectError(case.expected.value(), writer.writeMpint(case.input));
            try std.testing.expectEqual(@as(usize, 0), writer.off);
        },
        .client_kexinit,
        .client_packet,
        .client_channel_data_wrong_state,
        .client_channel_packet_too_large,
        .client_channel_receive_window,
        .client_channel_extended_truncated,
        .client_channel_window_overflow,
        .client_channel_close_disconnect,
        => try runClientCase(case, case_index),
    }
}

test "bounded deterministic malformed-input corpus" {
    try std.testing.expect(corpus.len <= max_steps);
    for (corpus, 0..) |case, case_index| {
        errdefer std.log.err(
            "malformed corpus case failed: {s} (seed=0x{x})",
            .{ case.name, corpus_seed +% case_index },
        );
        try std.testing.expect(case.input.len <= max_input_bytes);
        try runCase(case, case_index);
    }
}
