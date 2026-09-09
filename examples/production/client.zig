const std = @import("std");
const sshz = @import("sshz");
const common = @import("common.zig");

pub const HostKeyPolicy = struct {
    context: *anyopaque,
    verify_fn: *const fn (*anyopaque, []const u8, sshz.HostKeyInfo) anyerror!bool,
};

pub const Credentials = struct {
    context: *anyopaque,
    private_key_fn: ?*const fn (*anyopaque) anyerror!?[]const u8 = null,
    private_key_passphrase_fn: ?*const fn (*anyopaque) anyerror!?[]const u8 = null,
    password_fn: ?*const fn (*anyopaque) anyerror!?[]const u8 = null,
};

pub const Sink = struct {
    context: *anyopaque,
    data_fn: *const fn (*anyopaque, []const u8) anyerror!void,
    extended_data_fn: *const fn (*anyopaque, u32, []const u8) anyerror!void,
};

pub const Config = struct {
    username: []const u8,
    endpoint: []const u8,
    command: []const u8,
    limits: sshz.ResourceLimits,
    host_keys: HostKeyPolicy,
    credentials: Credentials,
    sink: Sink,
};

/// Returns the automatic command's durable terminal result.
///
/// Signal strings borrow client-owned storage through
/// `clearChannelExitResult(channel)` or `client.deinit()`.
pub fn commandExitResult(client: *const sshz.SshzClient) !sshz.ChannelExitResult {
    const channel = client.automaticSessionChannelId() orelse
        return error.AutomaticSessionNotOpened;
    return client.channelExitResult(channel) orelse error.RemoteCommandResultPending;
}

pub fn init(
    random: std.Random,
    allocator: std.mem.Allocator,
    config: *const Config,
    now: u64,
) !sshz.SshzClient {
    if (config.username.len == 0 or config.endpoint.len == 0 or config.command.len == 0)
        return error.InvalidConfiguration;
    try common.requireProductionLimits(config.limits);

    var client = try sshz.SshzClient.initWithLimits(
        random,
        config.username,
        allocator,
        config.limits,
    );
    errdefer client.deinit();
    // Exec is non-PTY by default, so stdout and extended-data stderr remain
    // distinct. Call setAutoPty as well only when terminal semantics are wanted.
    try client.setAutoExecCommand(config.command);
    try client.initializeDeadlines(now);
    return client;
}

fn provideOptional(
    client: *sshz.SshzClient,
    event: sshz.SshzClientEventCodes,
    provider: ?*const fn (*anyopaque) anyerror!?[]const u8,
    context: *anyopaque,
    comptime setter: enum { private_key, private_key_passphrase, password },
) !void {
    const value = if (provider) |get| try get(context) else null;
    if (value) |secret| {
        switch (setter) {
            .private_key => try client.setPrivateKey(secret),
            .private_key_passphrase => try client.setPrivateKeyPassphrase(secret),
            .password => try client.setAuthPassphrase(secret),
        }
    } else if (setter != .private_key) {
        return error.CredentialUnavailable;
    }
    try client.clearEvent(event);
}

fn handleEvent(
    client: *sshz.SshzClient,
    config: *const Config,
    event: sshz.SshzClientEventCodes,
) !common.PumpResult {
    switch (event) {
        .CheckHostKey => |key| {
            const accepted = key.raw_key != null and try config.host_keys.verify_fn(
                config.host_keys.context,
                config.endpoint,
                key,
            );
            if (accepted) try client.acceptHostKey() else try client.rejectHostKey();
        },
        .GetPrivateKey => try provideOptional(
            client,
            event,
            config.credentials.private_key_fn,
            config.credentials.context,
            .private_key,
        ),
        .GetKeyPassphrase => try provideOptional(
            client,
            event,
            config.credentials.private_key_passphrase_fn,
            config.credentials.context,
            .private_key_passphrase,
        ),
        .GetAuthPassphrase => try provideOptional(
            client,
            event,
            config.credentials.password_fn,
            config.credentials.context,
            .password,
        ),
        .KeyboardInteractive => return error.UnsupportedAuthenticationMethod,
        .RxData => |channel_data| {
            try config.sink.data_fn(config.sink.context, channel_data.data);
            try client.clearEvent(event);
        },
        .RxExtendedData => |extended| {
            try config.sink.extended_data_fn(
                config.sink.context,
                extended.data_type,
                extended.data,
            );
            try client.clearEvent(event);
        },
        .ChannelOpenRequest => |request| try client.rejectChannelOpen(
            request.channel,
            sshz.SshOpenFailureReason.AdministrativelyProhibited,
            "client policy rejects peer channel opens",
        ),
        .TcpipForwardSuccess,
        .TcpipForwardFailure,
        .CancelTcpipForwardSuccess,
        .CancelTcpipForwardFailure,
        .AgentChannelOpen,
        .AgentData,
        .AgentChannelClosed,
        .ChannelOpened,
        => return error.UnexpectedChannelEvent,
        .ChannelOpenFailure => return error.ChannelOpenFailed,
        .EndSession => {
            const result = try commandExitResult(client);
            switch (result) {
                .Status => |status| if (status != 0) return error.RemoteCommandFailed,
                .Signal => return error.RemoteCommandSignaled,
                .NoResult => return error.RemoteCommandResultMissing,
            }
            return .finished;
        },
        .ServerIdentification,
        .AuthMethodStarted,
        .Connected,
        .ChannelEof,
        .ChannelClosed,
        .Banner,
        => try client.clearEvent(event),
    }
    return .progress;
}

fn consume(
    client: *sshz.SshzClient,
    transport: common.Transport,
    scratch: []u8,
    requested: usize,
    now: u64,
) !common.PumpResult {
    if (scratch.len == 0) return error.EmptyScratchBuffer;
    const count = try transport.read(scratch[0..@min(scratch.len, requested)]);
    try client.write(scratch[0..count]);
    try client.noteActivity(now);
    return .progress;
}

fn produce(
    client: *sshz.SshzClient,
    transport: common.Transport,
    requested: usize,
    now: u64,
) !common.PumpResult {
    const bytes = try client.peek(requested);
    const count = try transport.write(bytes);
    try client.consumed(count);
    try client.noteActivity(now);
    return .progress;
}

/// Call only after polling the transport. The caller owns transport closure
/// and must `defer client.deinit()`; any returned error is terminal.
pub fn pumpOnce(
    client: *sshz.SshzClient,
    config: *const Config,
    transport: common.Transport,
    scratch: []u8,
    readiness: common.Readiness,
    now: u64,
) !common.PumpResult {
    if (try client.tick(now) != null) return error.DeadlineExpired;
    const next = client.getNextEvent() catch |err| switch (err) {
        error.NotReady => return .wait_read_or_write,
        else => return err,
    };
    return switch (next) {
        .Event => |event| try handleEvent(client, config, event),
        .ReadyToConsume => |count| if (readiness.readable)
            try consume(client, transport, scratch, count, now)
        else
            .wait_read,
        .ReadyToProduce => |count| if (readiness.writable)
            try produce(client, transport, count, now)
        else
            .wait_write,
        .ReadyToConsumeAndProduce => |counts| if (readiness.writable)
            try produce(client, transport, counts.produce, now)
        else if (readiness.readable)
            try consume(client, transport, scratch, counts.consume, now)
        else
            .wait_read_or_write,
    };
}

pub fn sendChannelData(
    client: *sshz.SshzClient,
    channel: u32,
    data: []const u8,
) !usize {
    if (data.len == 0) return 0;
    const destination = try client.getChannelWriteBuffer(channel);
    if (destination.len == 0) return error.NotReady;
    const count = @min(destination.len, data.len);
    @memcpy(destination[0..count], data[0..count]);
    try client.channelWriteComplete(channel, count);
    return count;
}

pub fn main(_: std.process.Init) !void {
    common.printCompileOnly("production client");
}

test "production client pump is compile-checked without network I/O" {
    const Mock = struct {
        fn verify(_: *anyopaque, _: []const u8, _: sshz.HostKeyInfo) !bool {
            return false;
        }

        fn data(_: *anyopaque, _: []const u8) !void {}

        fn extendedData(_: *anyopaque, _: u32, _: []const u8) !void {}

        fn read(_: *anyopaque, _: []u8) !usize {
            return error.UnexpectedRead;
        }

        fn write(_: *anyopaque, bytes: []const u8) !usize {
            return bytes.len;
        }

        fn close(_: *anyopaque) void {}
    };

    var context: u8 = 0;
    const limits: sshz.ResourceLimits = .{
        .deadlines = .{
            .handshake = 100,
            .authentication = 100,
            .idle = 100,
            .total_session = 100,
        },
        .key_lifetime = .{ .rekey_after_monotonic_ticks = 100 },
    };
    const config: Config = .{
        .username = "test",
        .endpoint = "example.invalid:22",
        .command = "true",
        .limits = limits,
        .host_keys = .{ .context = &context, .verify_fn = Mock.verify },
        .credentials = .{ .context = &context },
        .sink = .{
            .context = &context,
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

    var random = std.Random.DefaultPrng.init(1);
    var client = try init(random.random(), std.testing.allocator, &config, 0);
    defer client.deinit();
    var scratch: [8]u8 = undefined;
    try std.testing.expectEqual(
        common.PumpResult.progress,
        try pumpOnce(&client, &config, transport, &scratch, .{ .writable = true }, 0),
    );
}

const ProductionTestTransport = struct {
    // Normally model stream-accepted bytes waiting for the peer to read.
    // Buffered schedules instead treat this owned queue as unsent output.
    to_server: [16384]u8 = undefined,
    to_server_len: usize = 0,
    to_client: [3 * sshz.ResourceCapacities.packet_size]u8 = undefined,
    to_client_len: usize = 0,
    bytes_written: usize = 0,
    bytes_read: usize = 0,
    read_limit: usize = 7,

    fn verify(_: *anyopaque, _: []const u8, _: sshz.HostKeyInfo) !bool {
        return true;
    }

    fn data(_: *anyopaque, _: []const u8) !void {
        return error.UnexpectedChannelData;
    }

    fn extendedData(_: *anyopaque, _: u32, _: []const u8) !void {
        return error.UnexpectedChannelData;
    }

    fn read(context: *anyopaque, destination: []u8) !usize {
        const self: *@This() = @ptrCast(@alignCast(context));
        const count = @min(self.read_limit, destination.len, self.to_client_len);
        @memcpy(destination[0..count], self.to_client[0..count]);
        std.mem.copyForwards(u8, &self.to_client, self.to_client[count..self.to_client_len]);
        self.to_client_len -= count;
        self.bytes_read += count;
        return count;
    }

    fn write(context: *anyopaque, bytes: []const u8) !usize {
        const self: *@This() = @ptrCast(@alignCast(context));
        const count = @min(7, bytes.len, self.to_server.len - self.to_server_len);
        @memcpy(self.to_server[self.to_server_len..][0..count], bytes[0..count]);
        self.to_server_len += count;
        self.bytes_written += count;
        return count;
    }

    fn close(_: *anyopaque) void {}
};

const ProbeSchedule = struct {
    trigger: enum { ServerRequest, ExecEmitting, Connected, Header, Body } = .ServerRequest,
    prefer_read: bool = false,
    buffered: bool = false,
    stream_data: bool = false,
    resize_before_probe: enum { None, Queued, Advanced } = .None,
};

fn exerciseProductionKeepalive(shutdown: ?enum { Eof, Close }, exec_ack: bool, rekey: bool, schedule: ProbeSchedule) !void {
    const Loopback = ProductionTestTransport;
    const Delivery = struct {
        expected: []const u8,
        received: usize = 0,

        fn data(context: *anyopaque, bytes: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try std.testing.expect(bytes.len <= self.expected.len - self.received);
            try std.testing.expectEqualSlices(u8, self.expected[self.received..][0..bytes.len], bytes);
            self.received += bytes.len;
        }
    };
    var random = std.Random.DefaultPrng.init(2);
    var channel_data: [32768]u8 = undefined;
    if (schedule.stream_data) random.random().bytes(&channel_data);
    var delivery: Delivery = .{ .expected = if (schedule.stream_data) &channel_data else &.{} };
    var server = try sshz.SshzServer.initWithLimits(
        random.random(),
        @embedFile("production_test_host_key"),
        std.testing.allocator,
        .{ .key_lifetime = .{ .rekey_after_monotonic_ticks = if (rekey) 1 else null } },
    );
    defer server.deinit();
    try server.initializeDeadlines(0);
    var loopback: Loopback = .{};
    const config: Config = .{
        .username = "test",
        .endpoint = "example.invalid:22",
        .command = "true",
        .limits = .{
            .deadlines = .{ .handshake = 3000, .authentication = 3000, .idle = 3000, .total_session = 3000 },
            .key_lifetime = .{ .rekey_after_monotonic_ticks = 3000 },
        },
        .host_keys = .{ .context = &loopback, .verify_fn = Loopback.verify },
        .credentials = .{ .context = &loopback },
        .sink = .{ .context = &delivery, .data_fn = Delivery.data, .extended_data_fn = Loopback.extendedData },
    };
    const transport: common.Transport = .{
        .context = &loopback,
        .read_fn = Loopback.read,
        .write_fn = Loopback.write,
        .close_fn = Loopback.close,
    };
    var client = try init(random.random(), std.testing.allocator, &config, 0);
    defer client.deinit();
    try client.setTryNoneAuth(true);
    try client.setAutoExecAckEnabled(exec_ack);
    if (rekey) {
        try client.setAutoPty("xterm", 80, 24, 640, 480);
        try client.enableAgentForwarding();
    }
    var scratch: [64]u8 = undefined;
    var token: ?sshz.KeepaliveToken = null;
    var saw_partial = false;
    var command_requested = false;
    var shutdown_queued = false;
    var handoff_written: ?usize = null;
    var control_bytes: usize = 0;
    var reads_before_probe: usize = 0;
    var exec_partial = false;
    var exec_pending_through_rekey = false;
    var reply_start: usize = 0;
    var server_read: usize = 0;
    var probe_watermark: ?usize = null;
    var saw_duplex_read = false;
    var server_channel: ?u32 = null;
    var data_queued = false;
    for (0..2000) |step| {
        switch (try server.getNextEvent()) {
            .ReadyToConsume => |n| {
                const count = @min(n, loopback.to_server_len);
                const hold_flush = schedule.buffered and token != null and
                    (try client.keepaliveStatus(token.?)).transmission == .Emitting;
                const keys = server.keyLifetimeStatus();
                if (schedule.stream_data and !data_queued and server_channel != null and
                    server.isActive() and !keys.rekey_in_progress and !keys.local_rekey_pending)
                {
                    const buffer = try server.getChannelWriteBuffer(server_channel.?);
                    @memcpy(buffer[0..channel_data.len], &channel_data);
                    try server.channelWriteComplete(server_channel.?, channel_data.len);
                    data_queued = true;
                } else if (count != 0 and !hold_flush) {
                    try server.write(loopback.to_server[0..count]);
                    std.mem.copyForwards(u8, &loopback.to_server, loopback.to_server[count..loopback.to_server_len]);
                    loopback.to_server_len -= count;
                    server_read += count;
                }
            },
            .ReadyToProduce, .ReadyToConsumeAndProduce => {
                const bytes = try server.peek(loopback.to_client.len - loopback.to_client_len);
                const count = bytes.len;
                @memcpy(loopback.to_client[loopback.to_client_len..][0..count], bytes);
                loopback.to_client_len += count;
                try server.consumed(count);
            },
            .Event => |event| switch (event) {
                .UserAuth => try server.decideUserAuth(.Allow),
                .ChannelOpenRequest => |request| try server.acceptChannelOpen(request.channel),
                .Connected => try server.clearEvent(event),
                .WindowChange => try server.clearEvent(event),
                .ChannelRequest => |request| {
                    if (request.request == .Exec) {
                        command_requested = true;
                        server_channel = request.channel;
                        reply_start = loopback.bytes_read;
                        if (exec_ack) {
                            try std.testing.expectEqual(.Pending, (try client.autoExecAckStatus()).outcome);
                            try std.testing.expectEqual(.HandedToTransport, (try client.autoExecAckStatus()).transmission);
                        }
                        if (rekey) _ = try server.tick(2);
                    }
                    try server.clearEvent(event);
                },
                else => return error.UnexpectedServerEvent,
            },
        }
        const before_event = client.getNextEvent() catch |err| switch (err) {
            error.NotReady => null,
            else => return err,
        };
        const before = try client.autoExecAckStatus();
        const trigger = switch (schedule.trigger) {
            .ServerRequest => command_requested and client.isActive() and client.automaticSessionChannelId() != null,
            .ExecEmitting => before.transmission == .Emitting,
            .Connected => if (before_event) |event| event == .Event and event.Event == .Connected else false,
            .Header => command_requested and loopback.bytes_read > reply_start and loopback.bytes_read < reply_start + 16,
            .Body => command_requested and loopback.bytes_read > reply_start + 16 and before.outcome == .Pending,
        };
        if (token == null and trigger) {
            if (exec_ack) try std.testing.expectEqual(.Pending, before.outcome);
            const keys = client.keyLifetimeStatus();
            var retained: [sshz.ResourceCapacities.packet_size]u8 = undefined;
            const outgoing = if (before_event) |event| switch (event) {
                .ReadyToProduce, .ReadyToConsumeAndProduce => try client.peek(retained.len),
                else => &.{},
            } else &.{};
            const retained_len = outgoing.len;
            @memcpy(retained[0..retained_len], outgoing);
            if (schedule.resize_before_probe != .None) {
                client.session.sendWindowChange(100, 30, 800, 480);
                if (schedule.resize_before_probe == .Advanced) try client.advance();
            }
            token = try client.requestKeepalive();
            try std.testing.expectEqualDeep(keys.inbound, client.keyLifetimeStatus().inbound);
            if (retained_len != 0) {
                try std.testing.expectEqualSlices(u8, retained[0..retained_len], try client.peek(retained.len));
                try std.testing.expectEqualDeep(keys.outbound, client.keyLifetimeStatus().outbound);
            }
            reads_before_probe = loopback.bytes_read;
        }
        const current = client.getNextEvent() catch |err| switch (err) {
            error.NotReady => null,
            else => return err,
        };
        if (schedule.stream_data and command_requested and loopback.bytes_read >= reply_start + 32)
            loopback.read_limit = scratch.len;
        const read_first = schedule.prefer_read and loopback.to_client_len != 0 and
            current != null and current.? == .ReadyToConsumeAndProduce;
        if (read_first and token != null) saw_duplex_read = true;
        _ = try pumpOnce(&client, &config, transport, &scratch, .{
            .readable = loopback.to_client_len != 0 and (shutdown == null or token == null),
            .writable = loopback.to_server_len < loopback.to_server.len and !read_first,
        }, step);
        const exec_status = try client.autoExecAckStatus();
        if (exec_status.transmission == .Emitting) {
            exec_partial = true;
            try std.testing.expectEqual(.Pending, exec_status.outcome);
        }
        if (client.keyLifetimeStatus().rekey_in_progress and exec_status.outcome == .Pending)
            exec_pending_through_rekey = true;
        if (token) |id| {
            var status = try client.keepaliveStatus(id);
            if (status.transmission == .Emitting) saw_partial = true;
            if (shutdown) |control| {
                if (status.transmission == .Emitting and !shutdown_queued) {
                    const channel = client.automaticSessionChannelId().?;
                    switch (control) {
                        .Eof => try client.sendChannelEof(channel),
                        .Close => try client.sendChannelClose(channel),
                    }
                    try client.cancelKeepalive(id);
                    shutdown_queued = true;
                    status = try client.keepaliveStatus(id);
                }
            }
            if (status.transmission == .HandedToTransport and !status.transport_flushed) {
                if (probe_watermark == null) probe_watermark = loopback.bytes_written;
                // This adapter writes directly to the peer, without an unsent
                // queue. Buffered adapters must wait for their own watermark.
                if (!schedule.buffered or server_read >= probe_watermark.?) {
                    try client.markKeepaliveFlushed(id);
                    status = try client.keepaliveStatus(id);
                }
            }
            if (shutdown) |control| {
                if (status.transmission == .HandedToTransport) {
                    try std.testing.expect(shutdown_queued);
                    try std.testing.expect(status.outcome == .Cancelled);
                    try std.testing.expectEqual(reads_before_probe, loopback.bytes_read);
                    if (handoff_written) |written| {
                        if (loopback.bytes_written - written == control_bytes) {
                            if (control == .Eof) {
                                try std.testing.expect(try client.channelEofFlushed(client.automaticSessionChannelId().?));
                            }
                            try std.testing.expect((try client.getNextEvent()) == .ReadyToConsume);
                            return;
                        }
                    } else {
                        const next = try client.getNextEvent();
                        try std.testing.expect(next == .ReadyToConsumeAndProduce);
                        control_bytes = next.ReadyToConsumeAndProduce.produce;
                        try std.testing.expect(control_bytes > 0);
                        handoff_written = loopback.bytes_written;
                    }
                }
                continue;
            }
            if (status.outcome == .Acknowledged) {
                if (exec_ack and exec_status.outcome == .Pending) continue;
                if (!status.transport_flushed) continue;
                if (delivery.received != delivery.expected.len) continue;
                try std.testing.expect(saw_partial);
                try std.testing.expect(status.transport_flushed);
                try std.testing.expectEqual(sshz.KeepaliveReply.Failure, status.outcome.Acknowledged);
                if (exec_ack) {
                    try std.testing.expect(exec_partial);
                    try std.testing.expectEqual(.Accepted, exec_status.outcome);
                    try std.testing.expectEqual(client.automaticSessionChannelId().?, exec_status.channel.?);
                    if (rekey) {
                        try std.testing.expect(exec_pending_through_rekey);
                        try std.testing.expect(client.keyLifetimeStatus().inbound.epoch >= 2);
                    }
                } else try std.testing.expectEqual(.NotRequested, exec_status.outcome);
                if (schedule.prefer_read and schedule.trigger == .Header and !rekey)
                    try std.testing.expect(saw_duplex_read);
                try client.clearKeepalive(id);
                return;
            }
        }
    }
    return error.KeepaliveNotAcknowledged;
}

test "production pump explicitly observes keepalive after partial direct transport writes" {
    try exerciseProductionKeepalive(null, false, false, .{});
}

test "production encrypted exec acknowledgment survives rekey and concurrent keepalive" {
    try exerciseProductionKeepalive(null, true, false, .{});
    try exerciseProductionKeepalive(null, true, true, .{});
}

test "pre-acknowledgment probes preserve encrypted duplex packet boundaries" {
    for (std.enums.values(@FieldType(ProbeSchedule, "trigger"))) |trigger| {
        for ([_]bool{ false, true }) |read_first| {
            for ([_]bool{ false, true }) |buffered| {
                for ([_]bool{ false, true }) |rekey| {
                    try exerciseProductionKeepalive(null, true, rekey, .{
                        .trigger = trigger,
                        .prefer_read = read_first,
                        .buffered = buffered,
                        .stream_data = true,
                    });
                }
            }
        }
    }
}

test "queued resize and pre-acknowledgment probe preserve a received packet" {
    for ([_]@FieldType(ProbeSchedule, "trigger"){ .Header, .Body }) |trigger| {
        for ([_]@FieldType(ProbeSchedule, "resize_before_probe"){ .Queued, .Advanced }) |resize| {
            for ([_]bool{ false, true }) |buffered| {
                for ([_]bool{ false, true }) |stream_data| {
                    for ([_]bool{ false, true }) |rekey| {
                        try exerciseProductionKeepalive(null, true, rekey, .{
                            .trigger = trigger,
                            .prefer_read = true,
                            .buffered = buffered,
                            .stream_data = stream_data,
                            .resize_before_probe = resize,
                        });
                    }
                }
            }
        }
    }
}

test "production pump bounds large encrypted coalesced packets to the current read" {
    const Loopback = ProductionTestTransport;
    const sizes = [_]usize{ 32768, sshz.ResourceCapacities.channel_packet_size, 17 };
    const Delivery = struct {
        expected: []const u8,
        messages: usize = 0,

        fn data(context: *anyopaque, bytes: []const u8) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try std.testing.expect(self.messages < sizes.len);
            try std.testing.expectEqualSlices(u8, self.expected[0..sizes[self.messages]], bytes);
            self.messages += 1;
        }
    };
    var random = std.Random.DefaultPrng.init(69);
    var payload: [sshz.ResourceCapacities.channel_packet_size]u8 = undefined;
    random.random().bytes(&payload);
    var delivery: Delivery = .{ .expected = &payload };
    var server = try sshz.SshzServer.init(
        random.random(),
        @embedFile("production_test_host_key"),
        std.testing.allocator,
    );
    defer server.deinit();
    var loopback: Loopback = .{};
    const config: Config = .{
        .username = "test",
        .endpoint = "example.invalid:22",
        .command = "true",
        .limits = .{
            .deadlines = .{ .handshake = 3000, .authentication = 3000, .idle = 3000, .total_session = 3000 },
            .key_lifetime = .{ .rekey_after_monotonic_ticks = 3000 },
        },
        .host_keys = .{ .context = &loopback, .verify_fn = Loopback.verify },
        .credentials = .{ .context = &loopback },
        .sink = .{ .context = &delivery, .data_fn = Delivery.data, .extended_data_fn = Loopback.extendedData },
    };
    const transport: common.Transport = .{
        .context = &loopback,
        .read_fn = Loopback.read,
        .write_fn = Loopback.write,
        .close_fn = Loopback.close,
    };
    var client = try init(random.random(), std.testing.allocator, &config, 0);
    defer client.deinit();
    try client.setTryNoneAuth(true);
    var scratch: [32768]u8 = undefined;
    var channel: ?u32 = null;
    var sending = false;
    var sent: usize = 0;
    var packet_sizes: [sizes.len]usize = undefined;
    var batch_start: usize = 0;
    var initial_keys: ?sshz.KeyEpochStatus = null;
    var saw_partial_bodies: usize = 0;
    for (0..2000) |step| {
        switch (try server.getNextEvent()) {
            .ReadyToConsume => |n| {
                const count = @min(n, loopback.to_server_len);
                if (count != 0) {
                    try server.write(loopback.to_server[0..count]);
                    std.mem.copyForwards(u8, &loopback.to_server, loopback.to_server[count..loopback.to_server_len]);
                    loopback.to_server_len -= count;
                } else if (channel != null and sent < sizes.len) {
                    const buffer = try server.getChannelWriteBuffer(channel.?);
                    @memcpy(buffer[0..sizes[sent]], payload[0..sizes[sent]]);
                    try server.channelWriteComplete(channel.?, sizes[sent]);
                    sending = true;
                }
            },
            .ReadyToProduce, .ReadyToConsumeAndProduce => {
                const bytes = try server.peek(loopback.to_client.len - loopback.to_client_len);
                const count = bytes.len;
                try std.testing.expect(count > 0);
                @memcpy(loopback.to_client[loopback.to_client_len..][0..count], bytes);
                loopback.to_client_len += count;
                try server.consumed(count);
                if (sending) {
                    packet_sizes[sent] = count;
                    sent += 1;
                    sending = false;
                }
            },
            .Event => |event| switch (event) {
                .UserAuth => try server.decideUserAuth(.Allow),
                .ChannelOpenRequest => |request| try server.acceptChannelOpen(request.channel),
                .Connected => try server.clearEvent(event),
                .ChannelRequest => |request| {
                    if (request.request == .Exec) {
                        channel = request.channel;
                        try std.testing.expectEqual(@as(usize, 0), loopback.to_client_len);
                        batch_start = loopback.bytes_read;
                        initial_keys = client.keyLifetimeStatus().inbound;
                    }
                    try server.clearEvent(event);
                },
                else => return error.UnexpectedServerEvent,
            },
        }
        if (sent == sizes.len) {
            loopback.read_limit = scratch.len;
            const next = try client.getNextEvent();
            const requested = switch (next) {
                .ReadyToConsume => |n| n,
                .ReadyToConsumeAndProduce => |counts| counts.consume,
                else => null,
            };
            if (requested) |n| {
                var packet_offset = loopback.bytes_read - batch_start;
                for (packet_sizes) |packet_size| {
                    if (packet_offset >= packet_size) {
                        packet_offset -= packet_size;
                        continue;
                    }
                    // AES-CTR first reads its 16-byte block, then the remaining
                    // encrypted body and MAC. Coalesced packets stay upstream.
                    const expected = if (packet_offset < 16) 16 - packet_offset else packet_size - packet_offset;
                    try std.testing.expect(n > 0);
                    try std.testing.expectEqual(expected, n);
                    if (packet_offset == 16 + scratch.len) saw_partial_bodies += 1;
                    break;
                }
            }
        }
        _ = try pumpOnce(&client, &config, transport, &scratch, .{
            .readable = loopback.to_client_len != 0 and (channel == null or sent == sizes.len),
            .writable = loopback.to_server_len < loopback.to_server.len,
        }, step);
        if (delivery.messages == sizes.len) {
            try std.testing.expectEqual(@as(usize, 2), saw_partial_bodies);
            try std.testing.expectEqual(@as(usize, 0), loopback.to_client_len);
            try std.testing.expect(packet_sizes[0] > 16 + scratch.len);
            try std.testing.expect(packet_sizes[1] > 16 + scratch.len);
            var total: usize = 0;
            for (packet_sizes) |size| total += size;
            try std.testing.expectEqual(total, loopback.bytes_read - batch_start);
            const keys = client.keyLifetimeStatus().inbound;
            try std.testing.expectEqual(initial_keys.?.epoch, keys.epoch);
            try std.testing.expectEqual(initial_keys.?.encrypted_packets + sizes.len, keys.encrypted_packets);
            try std.testing.expectEqual(initial_keys.?.next_sequence_number + sizes.len, keys.next_sequence_number);
            try std.testing.expect(client.isActive());
            return;
        }
    }
    return error.CoalescedPacketsNotDelivered;
}

test "production pump flushes EOF and CLOSE behind a cancelled keepalive without peer input" {
    try exerciseProductionKeepalive(.Eof, false, false, .{});
    try exerciseProductionKeepalive(.Close, false, false, .{});
}

test "production pump discards unframed data across partial writes zero window and real rekey" {
    const Loopback = ProductionTestTransport;
    const SinkPolicy = struct {
        fn data(_: *anyopaque, bytes: []const u8) !void {
            try std.testing.expectEqualStrings("wake", bytes);
        }
    };
    var random = std.Random.DefaultPrng.init(3);
    var server = try sshz.SshzServer.initWithLimits(
        random.random(),
        @embedFile("production_test_host_key"),
        std.testing.allocator,
        .{ .initial_channel_window = 4, .channel_packet_size = 4 },
    );
    defer server.deinit();
    var loopback: Loopback = .{};
    const config: Config = .{
        .username = "test",
        .endpoint = "example.invalid:22",
        .command = "true",
        .limits = .{
            .deadlines = .{ .handshake = 30000, .authentication = 30000, .idle = 30000, .total_session = 30000 },
            .key_lifetime = .{ .rekey_after_monotonic_ticks = 3000 },
        },
        .host_keys = .{ .context = &loopback, .verify_fn = Loopback.verify },
        .credentials = .{ .context = &loopback },
        .sink = .{ .context = &loopback, .data_fn = SinkPolicy.data, .extended_data_fn = Loopback.extendedData },
    };
    const transport: common.Transport = .{
        .context = &loopback,
        .read_fn = Loopback.read,
        .write_fn = Loopback.write,
        .close_fn = Loopback.close,
    };
    var client = try init(random.random(), std.testing.allocator, &config, 0);
    defer client.deinit();
    try client.setTryNoneAuth(true);
    var scratch: [64]u8 = undefined;
    var command_requested = false;
    var submitted_at: ?usize = null;
    var suffix_discarded = false;
    var replacement_submitted = false;
    var wake_sent = false;
    var rekey_discarded = false;
    var token: ?sshz.KeepaliveToken = null;
    var received: [32]u8 = undefined;
    var received_len: usize = 0;
    var server_channel: ?u32 = null;
    for (0..4000) |step| {
        switch (try server.getNextEvent()) {
            .ReadyToConsume => |n| {
                const count = @min(n, loopback.to_server_len);
                if (count != 0) {
                    try server.write(loopback.to_server[0..count]);
                    std.mem.copyForwards(u8, &loopback.to_server, loopback.to_server[count..loopback.to_server_len]);
                    loopback.to_server_len -= count;
                } else if (received_len == 8 and !wake_sent) {
                    const destination = try server.getChannelWriteBuffer(server_channel.?);
                    try std.testing.expect(destination.len >= 4);
                    @memcpy(destination[0..4], "wake");
                    try server.channelWriteComplete(server_channel.?, 4);
                    wake_sent = true;
                }
            },
            .ReadyToProduce, .ReadyToConsumeAndProduce => {
                const bytes = try server.peek(loopback.to_client.len - loopback.to_client_len);
                const count = bytes.len;
                @memcpy(loopback.to_client[loopback.to_client_len..][0..count], bytes);
                loopback.to_client_len += count;
                try server.consumed(count);
            },
            .Event => |event| switch (event) {
                .UserAuth => try server.decideUserAuth(.Allow),
                .ChannelOpenRequest => |request| {
                    server_channel = request.channel;
                    try server.acceptChannelOpen(request.channel);
                },
                .Connected => try server.clearEvent(event),
                .ChannelRequest => |request| {
                    if (request.request == .Exec) command_requested = true;
                    try server.clearEvent(event);
                },
                .RxData => |data| {
                    try std.testing.expect(data.data.len <= received.len - received_len);
                    @memcpy(received[received_len..][0..data.data.len], data.data);
                    received_len += data.data.len;
                    try server.clearEvent(event);
                },
                else => return error.UnexpectedServerEvent,
            },
        }
        _ = try pumpOnce(&client, &config, transport, &scratch, .{
            .readable = loopback.to_client_len != 0,
            .writable = loopback.to_server_len < loopback.to_server.len,
        }, if (wake_sent) 10000 else step);
        const channel = client.automaticSessionChannelId() orelse continue;
        if (!command_requested) continue;
        if (submitted_at) |written| {
            if (!suffix_discarded and loopback.bytes_written > written) {
                const remaining = try client.peek(scratch.len);
                try std.testing.expect(remaining.len != 0);
                var before: [64]u8 = undefined;
                const remaining_len = remaining.len;
                @memcpy(before[0..remaining_len], remaining);
                const keys = client.keyLifetimeStatus();
                try std.testing.expectEqual(@as(usize, 7), try client.discardUnframedChannelWrite(channel));
                try std.testing.expectEqualDeep(keys, client.keyLifetimeStatus());
                try std.testing.expectEqualSlices(u8, before[0..remaining_len], try client.peek(scratch.len));
                suffix_discarded = true;
            }
        } else {
            try std.testing.expectEqual(@as(usize, 11), try sendChannelData(&client, channel, "keepdiscard"));
            submitted_at = loopback.bytes_written;
        }
        if (suffix_discarded and !replacement_submitted and
            (try client.getChannelWriteBuffer(channel)).len != 0)
        {
            // The first four-byte packet has been handed off, but its peer
            // credit cannot have returned during this same pump call.
            const keys = client.keyLifetimeStatus();
            try std.testing.expectEqual(@as(usize, 7), try sendChannelData(&client, channel, "blocked"));
            try std.testing.expectEqualDeep(keys, client.keyLifetimeStatus());
            try std.testing.expectEqual(@as(usize, 7), try client.discardUnframedChannelWrite(channel));
            try std.testing.expectEqual(@as(usize, 0), try client.discardUnframedChannelWrite(channel));
            try std.testing.expectEqual(@as(usize, 4), try sendChannelData(&client, channel, "new!"));
            replacement_submitted = true;
        }
        if (wake_sent and !rekey_discarded and client.keyLifetimeStatus().rekey_in_progress) {
            const next = client.getNextEvent() catch |err| switch (err) {
                error.NotReady => continue,
                else => return err,
            };
            if (next == .ReadyToConsume) {
                const keys = client.keyLifetimeStatus();
                try std.testing.expectEqual(@as(usize, 5), try sendChannelData(&client, channel, "rekey"));
                try std.testing.expectEqual(@as(usize, 5), try client.discardUnframedChannelWrite(channel));
                try std.testing.expectEqualDeep(keys, client.keyLifetimeStatus());
                rekey_discarded = true;
            }
        }
        if (rekey_discarded and !client.keyLifetimeStatus().rekey_in_progress and token == null) {
            try std.testing.expect(client.keyLifetimeStatus().outbound.epoch >= 2);
            token = try client.requestKeepalive();
        }
        if (token) |id| {
            if ((try client.keepaliveStatus(id)).outcome == .Acknowledged) {
                try std.testing.expectEqualStrings("keepnew!", received[0..received_len]);
                try std.testing.expect(client.isActive());
                return;
            }
        }
    }
    return error.DiscardScenarioIncomplete;
}
