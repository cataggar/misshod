const std = @import("std");
const Sshz = @import("sshz");
const SshzServer = Sshz.SshzServer;
const SshOpenFailureReason = Sshz.SshOpenFailureReason;
const auth = @import("auth.zig");

fn printUsage(program: []const u8) void {
    std.debug.print(
        \\Usage: {s} <port> <hostkey> [--authorized-keys <file> | --insecure-demo-auth]
        \\
        \\Authentication options:
        \\  --authorized-keys <file>  Authorize public keys globally from a plain authorized_keys file.
        \\                            Supported key types: ssh-ed25519,
        \\                            ecdsa-sha2-nistp256, and ssh-rsa.
        \\                            Key options and markers are not supported.
        \\  --insecure-demo-auth      INSECURE demo mode: accept any cryptographically verified
        \\                            public key, or a password equal to the username.
        \\
        \\With no authentication option, every authentication attempt is rejected.
        \\
    , .{program});
}

fn cliError(program: []const u8, comptime format: []const u8, args: anytype) noreturn {
    std.debug.print("Error: " ++ format ++ "\n\n", args);
    printUsage(program);
    std.process.exit(1);
}

fn readFd(fd: std.c.fd_t, buf: []u8) !usize {
    if (buf.len == 0) return 0;
    const n = std.c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    return @intCast(n);
}

fn writeFd(fd: std.c.fd_t, data: []const u8) !usize {
    if (data.len == 0) return 0;
    const n = std.c.write(fd, data.ptr, data.len);
    if (n < 0) return error.WriteFailed;
    return @intCast(n);
}

fn writeAllFd(fd: std.c.fd_t, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = try writeFd(fd, data[off..]);
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len == 2 and
        (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")))
    {
        printUsage(args[0]);
        std.process.exit(0);
    }
    if (args.len < 3) {
        printUsage(args[0]);
        std.process.exit(1);
    }

    var policy: auth.Policy = .deny_all;
    defer policy.deinit();
    var authorized_keys_path: ?[]const u8 = null;
    var insecure_demo_auth = false;
    var arg_index: usize = 3;
    while (arg_index < args.len) {
        const arg = args[arg_index];
        if (std.mem.eql(u8, arg, "--authorized-keys")) {
            if (authorized_keys_path != null) {
                cliError(args[0], "--authorized-keys may only be specified once", .{});
            }
            arg_index += 1;
            if (arg_index == args.len) {
                cliError(args[0], "--authorized-keys requires a file path", .{});
            }
            authorized_keys_path = args[arg_index];
        } else if (std.mem.eql(u8, arg, "--insecure-demo-auth")) {
            if (insecure_demo_auth) {
                cliError(args[0], "--insecure-demo-auth may only be specified once", .{});
            }
            insecure_demo_auth = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage(args[0]);
            std.process.exit(0);
        } else {
            cliError(args[0], "unknown option '{s}'", .{arg});
        }
        arg_index += 1;
    }

    if (authorized_keys_path != null and insecure_demo_auth) {
        cliError(
            args[0],
            "--authorized-keys and --insecure-demo-auth are mutually exclusive",
            .{},
        );
    }

    if (authorized_keys_path) |path| {
        const contents = std.Io.Dir.cwd().readFileAlloc(
            init.io,
            path,
            allocator,
            .limited(auth.MaxAuthorizedKeysFileBytes + 1),
        ) catch |err| {
            cliError(args[0], "cannot read authorized_keys file '{s}': {s}", .{ path, @errorName(err) });
        };
        const result = auth.AuthorizedKeys.parse(allocator, contents) catch |err| {
            cliError(args[0], "cannot load authorized_keys file '{s}': {s}", .{ path, @errorName(err) });
        };
        policy = switch (result) {
            .authorized_keys => |keys| .{ .authorized_keys = keys },
            .invalid => |failure| {
                if (failure.line == 0) {
                    cliError(args[0], "invalid authorized_keys file '{s}': {s}", .{ path, failure.reason.message() });
                }
                cliError(args[0], "invalid authorized_keys file '{s}' at line {d}: {s}", .{
                    path,
                    failure.line,
                    failure.reason.message(),
                });
            },
        };
        std.debug.print("Authentication policy: public keys from {s}\n", .{path});
    } else if (insecure_demo_auth) {
        policy = .insecure_demo;
        std.debug.print("WARNING: --insecure-demo-auth is enabled; authentication is intentionally insecure\n", .{});
    } else {
        std.debug.print("WARNING: no authentication policy configured; all authentication attempts will be rejected\n", .{});
    }

    const hostkey_ascii = std.Io.Dir.cwd().readFileAlloc(init.io, args[2], allocator, .limited(1024)) catch |err| {
        cliError(args[0], "cannot read host key file '{s}': {s}", .{ args[2], @errorName(err) });
    };
    defer allocator.free(hostkey_ascii);

    const port = std.fmt.parseInt(u16, args[1], 10) catch |err| {
        cliError(args[0], "invalid port '{s}': {s}", .{ args[1], @errorName(err) });
    };
    if (port == 0) {
        cliError(args[0], "port must be between 1 and 65535", .{});
    }

    if (hostkey_ascii.len == 0) {
        cliError(args[0], "host key file '{s}' is empty", .{args[2]});
    }

    switch (policy) {
        .authorized_keys => |keys| if (keys.blobs.len == 0) {
            std.debug.print("WARNING: authorized_keys file contains no keys; all authentication attempts will be rejected\n", .{});
        },
        else => {},
    }

    const addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var server = addr.listen(init.io, .{ .reuse_address = true }) catch |err| {
        cliError(args[0], "cannot listen on port {d}: {s}", .{ port, @errorName(err) });
    };
    defer server.deinit(init.io);

    std.debug.print("Server listening on port {d}\n", .{port});

    nextclient: while (true) {
        var stream = try server.accept(init.io);
        defer stream.close(init.io);

        // make a reasonable prng
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        try init.io.randomSecure(&seed);
        var prng = std.Random.DefaultCsprng.init(seed);

        var sshz = try SshzServer.init(prng.random(), hostkey_ascii, allocator);
        defer sshz.deinit();

        var iobuf: [8]u8 = undefined; // could be any size
        var quit = false;
        var pending_eof_channel: ?u32 = null;
        var pending_close_channel: ?u32 = null;
        var pipe: [2]std.c.fd_t = undefined;
        if (std.c.pipe(&pipe) != 0) return error.PipeFailed;
        defer _ = std.c.close(pipe[0]);
        defer _ = std.c.close(pipe[1]);

        ioloop: while (!quit) {
            const ev = try sshz.getNextEvent();
            switch (ev) {
                .Event => |eventCode| {
                    switch (eventCode) {
                        .Connected => {
                            std.debug.print("Connected!\n", .{});
                            try sshz.clearEvent(eventCode);
                        },
                        .RxData => |rxdata| {
                            try writeAllFd(std.c.STDOUT_FILENO, rxdata.data);

                            var response_buf: [1024]u8 = undefined;
                            const response = try std.fmt.bufPrint(&response_buf, "You said '{s}'\r\n", .{rxdata.data});
                            try writeAllFd(pipe[1], response);

                            try sshz.clearEvent(eventCode);
                            pending_eof_channel = rxdata.channel;
                        },
                        .EndSession => |reason| {
                            std.debug.print("Session ended: {any}\n", .{reason});
                            quit = true;
                            continue :ioloop;
                        },
                        .UserAuth => |credentials| {
                            const attempt: auth.Attempt = if (credentials.auth) |method| switch (method) {
                                .Password => |password| .{ .password = password },
                                .Pubkey => |pubkey| .{ .public_key = .{
                                    .algorithm = pubkey.algorithm,
                                    .blob = pubkey.blob,
                                } },
                            } else .none;
                            try sshz.decideUserAuth(
                                if (policy.allows(credentials.username, attempt)) .Allow else .Deny,
                            );
                        },
                        .GetPubkeyForUser => |username| {
                            std.debug.print(".GetPubkeyForUser: {s}\n", .{username});
                            std.debug.assert(false);
                        },
                        .ChannelRequest,
                        .ChannelEof,
                        .WindowChange,
                        .Signal,
                        .RxExtendedData,
                        .ChannelOpened,
                        .ChannelOpenFailure,
                        .AgentChannelOpen,
                        .AgentChannelClosed,
                        => {
                            try sshz.clearEvent(eventCode);
                        },
                        .PtyRequest => |request| {
                            try sshz.rejectPtyRequest(request.channel);
                        },
                        .ChannelOpenRequest => |request| {
                            switch (request.request) {
                                .Session => try sshz.acceptChannelOpen(request.channel),
                                else => try sshz.rejectChannelOpen(
                                    request.channel,
                                    SshOpenFailureReason.AdministrativelyProhibited,
                                    "unsupported channel open",
                                ),
                            }
                        },
                        .TcpipForward => {
                            try sshz.rejectTcpipForward();
                        },
                        .CancelTcpipForward => {
                            try sshz.rejectCancelTcpipForward();
                        },
                    }
                },
                .ReadyToConsume, .ReadyToProduce, .ReadyToConsumeAndProduce => {
                    const consume_len: usize = switch (ev) {
                        .ReadyToConsume => |n| n,
                        .ReadyToConsumeAndProduce => |s| s.consume,
                        else => 0,
                    };
                    const produce_len: usize = switch (ev) {
                        .ReadyToProduce => |n| n,
                        .ReadyToConsumeAndProduce => |s| s.produce,
                        else => 0,
                    };
                    _ = produce_len;

                    var pollevts: i16 = 0;
                    if (consume_len > 0) pollevts |= std.posix.POLL.IN;
                    if (ev == .ReadyToProduce or ev == .ReadyToConsumeAndProduce) pollevts |= std.posix.POLL.OUT;

                    var fds = [_]std.posix.pollfd{
                        .{
                            .fd = stream.socket.handle,
                            .events = pollevts,
                            .revents = undefined,
                        },
                        .{
                            .fd = pipe[0],
                            .events = std.posix.POLL.IN,
                            .revents = undefined,
                        },
                    };

                    const ready = std.posix.poll(&fds, 1000) catch 0;
                    if (ready > 0) {
                        if (fds[0].revents & std.posix.POLL.IN > 0 and consume_len > 0) { // socket is readable
                            var bytes_to_read = consume_len;
                            if (bytes_to_read > iobuf.len) {
                                bytes_to_read = iobuf.len;
                            }
                            const nbytes = try readFd(stream.socket.handle, iobuf[0..bytes_to_read]);
                            if (nbytes > 0) {
                                try sshz.write(iobuf[0..nbytes]);
                                continue :ioloop;
                            } else {
                                continue :nextclient;
                            }
                        }
                        if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                            const towrite = try sshz.peek(4);
                            const bytes_written = try writeFd(stream.socket.handle, towrite);
                            try sshz.consumed(bytes_written);
                            if (bytes_written == towrite.len) {
                                if (pending_eof_channel) |channel| {
                                    pending_eof_channel = null;
                                    pending_close_channel = channel;
                                    try sshz.sendChannelEof(channel);
                                } else if (pending_close_channel) |channel| {
                                    pending_close_channel = null;
                                    try sshz.sendChannelClose(channel);
                                }
                            }
                            continue :ioloop;
                        }
                        if (fds[1].revents & std.posix.POLL.IN > 0) { // data to be sent (from pipe)
                            const buf = try sshz.getChannelWriteBuffer(0);
                            if (buf.len > 0) {
                                const count = readFd(pipe[0], buf) catch 0;
                                if (count > 0) {
                                    try sshz.channelWriteComplete(0, count);
                                    continue :ioloop;
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}
