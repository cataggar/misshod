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
