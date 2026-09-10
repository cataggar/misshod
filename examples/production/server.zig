const std = @import("std");
const sshz = @import("sshz");
const common = @import("common.zig");

pub const Policy = struct {
    context: *anyopaque,
    authenticate_fn: *const fn (*anyopaque, sshz.UserCredentials) anyerror!bool,
    channel_open_fn: *const fn (*anyopaque, sshz.ChannelOpenRequestEvent) anyerror!bool,
    channel_request_fn: *const fn (*anyopaque, sshz.ChannelRequestEvent) anyerror!bool,
    window_change_fn: *const fn (*anyopaque, sshz.WindowSize) anyerror!bool,
    signal_fn: *const fn (*anyopaque, sshz.ChannelSignal) anyerror!bool,
    data_fn: *const fn (*anyopaque, sshz.ChannelData) anyerror!void,
    extended_data_fn: *const fn (*anyopaque, sshz.ChannelExtendedData) anyerror!void,
    pty_request_fn: ?*const fn (*anyopaque, sshz.PtyRequest) anyerror!bool = null,
    channel_eof_fn: ?*const fn (*anyopaque, u32) anyerror!void = null,
};

pub const Config = struct {
    limits: sshz.ResourceLimits,
    policy: Policy,
    channel_events_enabled: bool = false,
};

pub fn init(
    random: std.Random,
    host_private_key: []const u8,
    allocator: std.mem.Allocator,
    config: *const Config,
    now: u64,
) !sshz.SshzServer {
    if (host_private_key.len == 0) return error.InvalidConfiguration;
    try common.requireProductionLimits(config.limits);

    var server = try sshz.SshzServer.initWithLimits(
        random,
        host_private_key,
        allocator,
        config.limits,
    );
    errdefer server.deinit();
    try server.setServerChannelEventsEnabled(config.channel_events_enabled);
    try server.initializeDeadlines(now);
    return server;
}

fn handleEvent(
    server: *sshz.SshzServer,
    config: *const Config,
    event: sshz.SshzServerEventCodes,
) !common.PumpResult {
    switch (event) {
        .UserAuth => |credentials| {
            const accepted = try config.policy.authenticate_fn(
                config.policy.context,
                credentials,
            );
            try server.decideUserAuth(if (accepted) .Allow else .Deny);
        },
        .ChannelOpenRequest => |request| {
            const accepted = try config.policy.channel_open_fn(
                config.policy.context,
                request,
            );
            if (accepted) {
                try server.acceptChannelOpen(request.channel);
            } else {
                try server.rejectChannelOpen(
                    request.channel,
                    sshz.SshOpenFailureReason.AdministrativelyProhibited,
                    "channel denied by application policy",
                );
            }
        },
        .ChannelRequest => |request| {
            const accepted = try config.policy.channel_request_fn(
                config.policy.context,
                request,
            );
            if (!accepted) try server.sendChannelClose(request.channel);
            try server.clearEvent(event);
        },
        .PtyRequest => |request| {
            const accepted = if (config.policy.pty_request_fn) |callback|
                try callback(config.policy.context, request)
            else
                false;
            if (accepted) {
                try server.acceptPtyRequest(request.channel);
            } else {
                try server.rejectPtyRequest(request.channel);
            }
        },
        .ChannelEof => |channel| {
            if (config.policy.channel_eof_fn) |callback| try callback(config.policy.context, channel);
            try server.clearEvent(event);
        },
        .RxData => |data| {
            try config.policy.data_fn(config.policy.context, data);
            try server.clearEvent(event);
        },
        .RxExtendedData => |data| {
            try config.policy.extended_data_fn(config.policy.context, data);
            try server.clearEvent(event);
        },
        .WindowChange => |window| {
            const accepted = try config.policy.window_change_fn(
                config.policy.context,
                window,
            );
            if (!accepted) try server.sendChannelClose(window.channel);
            try server.clearEvent(event);
        },
        .Signal => |signal| {
            const accepted = try config.policy.signal_fn(
                config.policy.context,
                signal,
            );
            if (!accepted) try server.sendChannelClose(signal.channel);
            try server.clearEvent(event);
        },
        .TcpipForward => try server.rejectTcpipForward(),
        .CancelTcpipForward => try server.rejectCancelTcpipForward(),
        .GetPubkeyForUser => return error.UnsupportedAuthenticationEvent,
        .ChannelOpened,
        .ChannelOpenFailure,
        .AgentChannelOpen,
        .AgentChannelClosed,
        => return error.UnexpectedOutboundChannelEvent,
        .EndSession => return .finished,
        .Connected,
        => try server.clearEvent(event),
    }
    return .progress;
}

fn consume(
    server: *sshz.SshzServer,
    transport: common.Transport,
    scratch: []u8,
    requested: usize,
    now: u64,
) !common.PumpResult {
    if (scratch.len == 0) return error.EmptyScratchBuffer;
    const count = try transport.read(scratch[0..@min(scratch.len, requested)]);
    try server.write(scratch[0..count]);
    try server.noteActivity(now);
    return .progress;
}

fn produce(
    server: *sshz.SshzServer,
    transport: common.Transport,
    requested: usize,
    now: u64,
) !common.PumpResult {
    const bytes = try server.peek(requested);
    const count = try transport.write(bytes);
    try server.consumed(count);
    try server.noteActivity(now);
    return .progress;
}

/// Call only after polling the transport. The caller owns transport closure
/// and must `defer server.deinit()`; any returned error is terminal.
pub fn pumpOnce(
    server: *sshz.SshzServer,
    config: *const Config,
    transport: common.Transport,
    scratch: []u8,
    readiness: common.Readiness,
    now: u64,
) !common.PumpResult {
    if (try server.tick(now) != null) return error.DeadlineExpired;
    const next = server.getNextEvent() catch |err| switch (err) {
        error.NotReady => return .wait_read_or_write,
        else => return err,
    };
    return switch (next) {
        .Event => |event| try handleEvent(server, config, event),
        .ReadyToConsume => |count| if (readiness.readable)
            try consume(server, transport, scratch, count, now)
        else
            .wait_read,
        .ReadyToProduce => |count| if (readiness.writable)
            try produce(server, transport, count, now)
        else
            .wait_write,
        .ReadyToConsumeAndProduce => |counts| if (readiness.writable)
            try produce(server, transport, counts.produce, now)
        else if (readiness.readable)
            try consume(server, transport, scratch, counts.consume, now)
        else
            .wait_read_or_write,
    };
}

pub fn sendChannelData(
    server: *sshz.SshzServer,
    channel: u32,
    data: []const u8,
) !usize {
    if (data.len == 0) return 0;
    const destination = try server.getChannelWriteBuffer(channel);
    if (destination.len == 0) return error.NotReady;
    const count = @min(destination.len, data.len);
    @memcpy(destination[0..count], data[0..count]);
    try server.channelWriteComplete(channel, count);
    return count;
}

pub fn main(_: std.process.Init) !void {
    common.printCompileOnly("production server");
}

test "production server pump is compile-checked without network I/O" {
    const Mock = struct {
        fn authenticate(_: *anyopaque, _: sshz.UserCredentials) !bool {
            return false;
        }

        fn channelOpen(_: *anyopaque, _: sshz.ChannelOpenRequestEvent) !bool {
            return false;
        }

        fn channelRequest(_: *anyopaque, _: sshz.ChannelRequestEvent) !bool {
            return false;
        }

        fn windowChange(_: *anyopaque, _: sshz.WindowSize) !bool {
            return false;
        }

        fn signal(_: *anyopaque, _: sshz.ChannelSignal) !bool {
            return false;
        }

        fn data(_: *anyopaque, _: sshz.ChannelData) !void {}

        fn extendedData(_: *anyopaque, _: sshz.ChannelExtendedData) !void {}

        fn read(_: *anyopaque, _: []u8) !usize {
            return error.UnexpectedRead;
        }

        fn write(_: *anyopaque, bytes: []const u8) !usize {
            return bytes.len;
        }

        fn close(_: *anyopaque) void {}
    };

    var context: u8 = 0;
    const config: Config = .{
        .limits = .{
            .deadlines = .{
                .handshake = 100,
                .authentication = 100,
                .idle = 100,
                .total_session = 100,
            },
            .key_lifetime = .{ .rekey_after_monotonic_ticks = 100 },
        },
        .policy = .{
            .context = &context,
            .authenticate_fn = Mock.authenticate,
            .channel_open_fn = Mock.channelOpen,
            .channel_request_fn = Mock.channelRequest,
            .window_change_fn = Mock.windowChange,
            .signal_fn = Mock.signal,
            .data_fn = Mock.data,
            .extended_data_fn = Mock.extendedData,
        },
    };
    const transport: common.Transport = .{
        .context = &context,
        .read_fn = Mock.read,
        .write_fn = Mock.write,
        .close_fn = Mock.close,
    };

    var random = std.Random.DefaultPrng.init(2);
    var server = try init(
        random.random(),
        @embedFile("production_test_host_key"),
        std.testing.allocator,
        &config,
        0,
    );
    defer server.deinit();
    var scratch: [8]u8 = undefined;
    try std.testing.expectEqual(
        common.PumpResult.wait_read,
        try pumpOnce(&server, &config, transport, &scratch, .{}, 0),
    );
}

const ExecutionTestQueue = struct {
    bytes: [2 * sshz.ResourceCapacities.packet_size]u8 = undefined,
    len: usize = 0,

    fn produce(self: *@This(), peer: anytype, available: usize) !void {
        const bytes = try peer.peek(@min(7, available, self.bytes.len - self.len));
        if (bytes.len == 0) return error.TestQueueFull;
        @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
        try peer.consumed(bytes.len);
    }

    fn consume(self: *@This(), peer: anytype, available: usize) !void {
        const count = @min(7, available, self.len);
        if (count == 0) return;
        try peer.write(self.bytes[0..count]);
        std.mem.copyForwards(u8, &self.bytes, self.bytes[count..self.len]);
        self.len -= count;
    }
};

fn offerExecutionTestData(peer: anytype, channel: u32, data: []const u8, extended: bool) !bool {
    const buffer = try peer.getChannelWriteBuffer(channel);
    if (buffer.len == 0) return false;
    try std.testing.expect(buffer.len >= data.len);
    @memcpy(buffer[0..data.len], data);
    const submission = if (extended)
        peer.channelExtendedWriteComplete(channel, 1, data.len)
    else
        peer.channelWriteComplete(channel, data.len);
    submission catch |err| switch (err) {
        error.cannotAcceptWrite => return false,
        else => return err,
    };
    return true;
}

fn exerciseOwnedServerExecution(pty: bool, signal: bool, rekey: bool) !void {
    var random = std.Random.DefaultPrng.init(11);
    const limits: sshz.ResourceLimits = .{
        .initial_channel_window = 8,
        .channel_packet_size = 4,
        .key_lifetime = .{ .rekey_after_monotonic_ticks = if (rekey) 10 else null },
    };
    var server = try sshz.SshzServer.initWithLimits(random.random(), @embedFile("production_test_host_key"), std.testing.allocator, limits);
    defer server.deinit();
    var client = try sshz.SshzClient.initWithLimits(random.random(), "test", std.testing.allocator, limits);
    defer client.deinit();
    try server.initializeDeadlines(0);
    try client.initializeDeadlines(0);
    try server.setServerChannelEventsEnabled(true);
    try server.setAutoChannelReadCreditEnabled(false);
    try client.setAutoChannelReadCreditEnabled(false);
    try client.setTryNoneAuth(true);
    try client.setAutoExecCommand("command");
    try client.setAutoExecAckEnabled(true);
    if (pty) try client.setAutoPty("xterm", 80, 24, 640, 480);
    var to_server: ExecutionTestQueue = .{};
    var to_client: ExecutionTestQueue = .{};
    var server_channel: ?u32 = null;
    var connected = false;
    var saw_pty = false;
    var input_sent = false;
    var input_received: usize = 0;
    var stdout_received: usize = 0;
    var stderr_received: usize = 0;
    var server_eofs: usize = 0;
    var client_eofs: usize = 0;
    var output_phase: u8 = 0;
    var credit_returned = false;
    var saw_result_emitting = false;
    var server_ended = false;
    var client_ended = false;
    var token: ?sshz.KeepaliveToken = null;
    for (0..20_000) |step| {
        if (!server_ended) switch (try server.getNextEvent()) {
            .ReadyToConsume => |count| try to_server.consume(&server, count),
            .ReadyToProduce => |count| try to_client.produce(&server, count),
            .ReadyToConsumeAndProduce => |counts| {
                if (to_server.len != 0 and step % 2 == 0)
                    try to_server.consume(&server, counts.consume)
                else
                    try to_client.produce(&server, counts.produce);
            },
            .Event => |event| switch (event) {
                .UserAuth => try server.decideUserAuth(.Allow),
                .ChannelOpenRequest => |request| try server.acceptChannelOpen(request.channel),
                .PtyRequest => |request| {
                    try std.testing.expect(pty);
                    try std.testing.expectEqualStrings("xterm", request.term);
                    try std.testing.expectEqual(@as(u32, 80), request.cols);
                    try std.testing.expectEqual(@as(u32, 24), request.rows);
                    try std.testing.expect(request.modes.len > 1);
                    try std.testing.expectEqual(@as(u8, 0), request.modes[request.modes.len - 1]);
                    saw_pty = true;
                    try server.acceptPtyRequest(request.channel);
                },
                .ChannelRequest => |request| {
                    try std.testing.expect(request.request == .Exec);
                    try std.testing.expectEqualStrings("command", request.request.Exec);
                    try std.testing.expectEqual(pty, saw_pty);
                    try std.testing.expectEqual(.Pending, (try client.autoExecAckStatus()).outcome);
                    server_channel = request.channel;
                    try server.clearEvent(event);
                },
                .RxData => |data| {
                    try std.testing.expectEqualSlices(u8, "input123"[input_received..][0..data.data.len], data.data);
                    input_received += data.data.len;
                    try server.clearEvent(event);
                },
                .ChannelEof => |channel| {
                    try std.testing.expectEqual(server_channel.?, channel);
                    try std.testing.expectEqual(@as(usize, 8), input_received);
                    server_eofs += 1;
                    try server.clearEvent(event);
                },
                .Connected => try server.clearEvent(event),
                .EndSession => server_ended = true,
                else => return error.UnexpectedServerEvent,
            },
        };
        if (!client_ended) switch (try client.getNextEvent()) {
            .ReadyToConsume => |count| try to_client.consume(&client, count),
            .ReadyToProduce => |count| try to_server.produce(&client, count),
            .ReadyToConsumeAndProduce => |counts| {
                if (to_client.len != 0 and step % 2 != 0)
                    try to_client.consume(&client, counts.consume)
                else
                    try to_server.produce(&client, counts.produce);
            },
            .Event => |event| switch (event) {
                .CheckHostKey => try client.acceptHostKey(),
                .ServerIdentification, .AuthMethodStarted => try client.clearEvent(event),
                .Connected => {
                    connected = true;
                    try client.clearEvent(event);
                    try std.testing.expectEqual(.Pending, (try client.autoExecAckStatus()).outcome);
                    token = try client.requestKeepalive();
                },
                .RxData => |data| {
                    try std.testing.expectEqualSlices(u8, "stdout"[stdout_received..][0..data.data.len], data.data);
                    stdout_received += data.data.len;
                    try client.clearEvent(event);
                },
                .RxExtendedData => |data| {
                    try std.testing.expectEqual(@as(u32, 1), data.data_type);
                    try std.testing.expectEqual(@as(usize, 6), stdout_received);
                    try std.testing.expectEqualSlices(u8, "stderr"[stderr_received..][0..data.data.len], data.data);
                    stderr_received += data.data.len;
                    try client.clearEvent(event);
                },
                .ChannelEof => |channel| {
                    try std.testing.expectEqual(@as(usize, 6), stdout_received);
                    try std.testing.expectEqual(@as(usize, 6), stderr_received);
                    const result = client.channelExitResult(channel).?;
                    if (signal) {
                        try std.testing.expectEqualStrings("TERM", result.Signal.signal_name);
                        try std.testing.expect(result.Signal.core_dumped);
                        try std.testing.expectEqualStrings("stopped", result.Signal.error_message);
                        try std.testing.expectEqualStrings("en", result.Signal.language_tag);
                    } else try std.testing.expectEqual(@as(u32, 37), result.Status);
                    client_eofs += 1;
                    try client.sendChannelClose(channel);
                    try client.clearEvent(event);
                },
                .ChannelClosed => try client.clearEvent(event),
                .EndSession => client_ended = true,
                else => return error.UnexpectedClientEvent,
            },
        };
        if (connected and !input_sent) {
            input_sent = try offerExecutionTestData(&client, client.automaticSessionChannelId().?, "input123", false);
            if (input_sent) try client.sendChannelEof(client.automaticSessionChannelId().?);
        }
        if (server_channel) |channel| {
            if (output_phase == 0 and try offerExecutionTestData(&server, channel, "stdout", false)) output_phase = 1;
            if (output_phase == 1 and try offerExecutionTestData(&server, channel, "stderr", true)) {
                if (signal) {
                    var name = "TERM".*;
                    var message = "stopped".*;
                    try server.sendChannelExitSignal(channel, .{
                        .signal_name = &name,
                        .core_dumped = true,
                        .error_message = &message,
                        .language_tag = "en",
                    });
                    @memset(&name, 'x');
                    @memset(&message, 'x');
                } else try server.sendChannelExitStatus(channel, 37);
                if (rekey) _ = try server.tick(11);
                try server.sendChannelEof(channel);
                output_phase = 2;
            }
            if (server.serverChannelExitStatus(channel)) |status| {
                if (status.transmission == .Emitting) saw_result_emitting = true;
            }
        }
        if (stdout_received + stderr_received == 8 and !credit_returned and token != null and
            (try client.keepaliveStatus(token.?)).outcome == .Acknowledged)
        {
            try std.testing.expectEqual(.Queued, server.serverChannelExitStatus(server_channel.?).?.transmission);
            try client.channelReadConsumed(client.automaticSessionChannelId().?, 8);
            credit_returned = true;
        }
        if (server_ended and client_ended) {
            try std.testing.expectEqual(@as(usize, 1), server_eofs);
            try std.testing.expectEqual(@as(usize, 1), client_eofs);
            try std.testing.expect(credit_returned and saw_result_emitting);
            try std.testing.expectEqual(.Accepted, (try client.autoExecAckStatus()).outcome);
            const retained = server.serverChannelExitStatus(server_channel.?).?;
            try std.testing.expectEqual(.HandedToTransport, retained.transmission);
            try std.testing.expect(!retained.abandoned);
            try std.testing.expect(server.clearServerChannelExitStatus(server_channel.?));
            try std.testing.expect(client.clearChannelExitResult(client.automaticSessionChannelId().?));
            if (rekey) {
                try std.testing.expect(server.keyLifetimeStatus().outbound.epoch >= 2);
                try std.testing.expect(client.keyLifetimeStatus().inbound.epoch >= 2);
            }
            return;
        }
    }
    return error.ExecutionDidNotComplete;
}

test "production server owned execution over encrypted manual flow control" {
    for ([_]bool{ false, true }) |pty| {
        for ([_]bool{ false, true }) |signal| try exerciseOwnedServerExecution(pty, signal, false);
    }
}

test "production server owned execution drains data result and EOF through real rekey" {
    for ([_]bool{ false, true }) |pty| {
        for ([_]bool{ false, true }) |signal| try exerciseOwnedServerExecution(pty, signal, true);
    }
}
