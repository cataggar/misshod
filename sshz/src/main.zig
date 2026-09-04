const std = @import("std");
const posix = std.posix;
const Sshz = @import("sshz");
const SshzClient = Sshz.SshzClient;
const SshOpenFailureReason = Sshz.SshOpenFailureReason;
const known_hosts = @import("known_hosts.zig");

const HostKeyMode = enum {
    strict,
    accept_new,
    insecure_demo,
};

fn printUsage(program: []const u8) void {
    std.debug.print(
        \\Usage: {s} <username@host> <port> [options] [idfile]
        \\
        \\Host key verification (strict by default):
        \\  --host-key-mode <strict|accept-new|insecure-demo>
        \\  --strict-host-key-checking  Require a matching known_hosts entry
        \\  --accept-new                Add new hosts, but reject changed keys
        \\  --insecure-demo             DANGEROUS: accept every host key
        \\  --known-hosts <path>        Override $HOME/.ssh/known_hosts
        \\
        \\Other options:
        \\  -A, --agent-forward         Forward the local SSH agent
        \\  -h, --help                  Show this help
        \\
    , .{program});
}

fn parseHostKeyMode(value: []const u8) !HostKeyMode {
    if (std.mem.eql(u8, value, "strict")) return .strict;
    if (std.mem.eql(u8, value, "accept-new")) return .accept_new;
    if (std.mem.eql(u8, value, "insecure-demo") or std.mem.eql(u8, value, "insecure")) {
        return .insecure_demo;
    }
    return error.InvalidHostKeyMode;
}

fn selectHostKeyMode(
    selected: *?HostKeyMode,
    mode: HostKeyMode,
) !void {
    if (selected.*) |previous| {
        if (previous != mode) return error.ConflictingHostKeyModes;
    }
    selected.* = mode;
}

fn printHostKeyMismatch(
    endpoint: []const u8,
    path: []const u8,
    fingerprint: []const u8,
) void {
    std.debug.print(
        \\HOST KEY VERIFICATION FAILED: the key for {s} does not match {s}
        \\Presented fingerprint: SHA256:{s}
        \\Refusing to authenticate. Remove the stale entry manually after verifying the new key;
        \\accept-new will not replace a changed key.
        \\
    , .{ endpoint, path, fingerprint });
}

fn printHostKeyUnknown(
    endpoint: []const u8,
    path: []const u8,
    fingerprint: []const u8,
) void {
    std.debug.print(
        \\HOST KEY VERIFICATION FAILED: no trusted key for {s} in {s}
        \\Presented fingerprint: SHA256:{s}
        \\Verify the fingerprint, then rerun with --accept-new to add this host.
        \\
    , .{ endpoint, path, fingerprint });
}

// Turn off echo and read a password
fn readPassphrase(password_buf: []u8) ![]u8 {
    const stdin_fd = std.c.STDIN_FILENO;

    if (std.c.isatty(stdin_fd) != 0) {
        // disable terminal echo
        var termios = try std.posix.tcgetattr(stdin_fd);
        termios.lflag.ECHO = false;
        try std.posix.tcsetattr(stdin_fd, .FLUSH, termios);
        const password = try readLine(stdin_fd, password_buf);
        // re-enable echo
        termios.lflag.ECHO = true;
        try std.posix.tcsetattr(stdin_fd, .FLUSH, termios);
        try writeAllFd(std.c.STDOUT_FILENO, "\n");
        return password;
    } else {
        return try readLine(stdin_fd, password_buf);
    }
}

fn envOrReadPassphrase(init: std.process.Init, name: []const u8, prompt: []const u8, password_buf: []u8) ![]const u8 {
    if (init.environ_map.get(name)) |value| {
        return value;
    }

    std.debug.print("{s}", .{prompt});
    return try readPassphrase(password_buf);
}

var original_termios: ?std.posix.termios = null;
const MaxAgentSockets = 4;

const AgentSocket = struct {
    channel: u32,
    fd: std.c.fd_t,
};

pub fn raw_mode_start() !void {
    const handle = std.c.STDIN_FILENO;

    if (std.c.isatty(handle) != 0) {
        var termios = try std.posix.tcgetattr(handle);
        original_termios = termios;

        termios.iflag.BRKINT = false;
        termios.iflag.ICRNL = true;
        termios.iflag.INPCK = false;
        termios.iflag.ISTRIP = false;
        termios.iflag.IXON = false;
        termios.oflag.OPOST = true;
        termios.lflag.ECHO = false;
        termios.lflag.ICANON = false;
        termios.lflag.IEXTEN = false;
        termios.lflag.ISIG = false;
        termios.cflag.CSIZE = .CS8;
        termios.cc[@intFromEnum(std.posix.V.TIME)] = 0;
        termios.cc[@intFromEnum(std.posix.V.MIN)] = 1;

        try std.posix.tcsetattr(handle, .FLUSH, termios);
    }
}

pub fn raw_mode_stop() void {
    if (original_termios) |termios| {
        std.posix.tcsetattr(std.c.STDIN_FILENO, .FLUSH, termios) catch {};
    }
    writeAllFd(std.c.STDOUT_FILENO, "\n") catch {};
}

fn connectAgentSocket(path: []const u8) !std.c.fd_t {
    const fd = std.c.socket(std.c.AF.UNIX, std.c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = std.c.close(fd);

    var addr: std.c.sockaddr.un = undefined;
    addr.family = std.c.AF.UNIX;
    @memset(&addr.path, 0);
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);

    const addr_len: std.c.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + path.len + 1);
    if (std.c.connect(fd, @ptrCast(&addr), addr_len) != 0) return error.ConnectFailed;
    return fd;
}

fn connectTcp(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.parse(host, port)) |address| {
        return try address.connect(io, .{ .mode = .stream });
    } else |_| {}

    const host_name = try std.Io.net.HostName.init(host);
    var results_buffer: [16]std.Io.net.IpAddress.ConnectError!std.Io.net.Stream = undefined;
    var results: std.Io.Queue(std.Io.net.IpAddress.ConnectError!std.Io.net.Stream) = .init(&results_buffer);
    try std.Io.net.HostName.connectMany(host_name, io, port, &results, .{ .mode = .stream });

    var last_err: ?anyerror = null;
    while (true) {
        const result = results.getOne(io) catch |err| switch (err) {
            error.Closed => break,
            else => |e| return e,
        };
        const stream = result catch |err| {
            last_err = err;
            continue;
        };
        return stream;
    }
    if (last_err) |err| return err;
    return error.NoAddressReturned;
}

fn readFd(fd: std.c.fd_t, buf: []u8) !usize {
    if (buf.len == 0) return 0;
    const n = std.c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    return @intCast(n);
}

fn readLine(fd: std.c.fd_t, buf: []u8) ![]u8 {
    var n: usize = 0;
    while (n < buf.len) {
        const count = try readFd(fd, buf[n .. n + 1]);
        if (count == 0) break;
        if (buf[n] == '\n') break;
        n += 1;
    }
    return buf[0..n];
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
        const n = std.c.write(fd, data[off..].ptr, data.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}

fn addAgentSocket(sockets: *[MaxAgentSockets]?AgentSocket, channel: u32, path: []const u8) !void {
    var free_slot: ?*?AgentSocket = null;
    for (sockets) |*slot| {
        if (slot.* == null) {
            free_slot = slot;
            break;
        }
    }
    const slot = free_slot orelse return error.AgentSocketTableFull;
    slot.* = .{ .channel = channel, .fd = try connectAgentSocket(path) };
}

fn findAgentSocket(sockets: *[MaxAgentSockets]?AgentSocket, channel: u32) ?*AgentSocket {
    for (sockets) |*slot| {
        if (slot.*) |*agent| {
            if (agent.channel == channel) return agent;
        }
    }
    return null;
}

fn closeAgentSocket(sockets: *[MaxAgentSockets]?AgentSocket, channel: u32) void {
    for (sockets) |*slot| {
        if (slot.*) |agent| {
            if (agent.channel == channel) {
                _ = std.c.close(agent.fd);
                slot.* = null;
                return;
            }
        }
    }
}

fn closeAllAgentSockets(sockets: *[MaxAgentSockets]?AgentSocket) void {
    for (sockets) |*slot| {
        if (slot.*) |agent| {
            _ = std.c.close(agent.fd);
            slot.* = null;
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage(args[0]);
            return;
        }
    }

    if (args.len < 3) {
        printUsage(args[0]);
        std.process.exit(1);
    }

    const user_host = args[1];
    const port = std.fmt.parseInt(u16, args[2], 10) catch {
        std.debug.print("Invalid SSH port: {s}\n", .{args[2]});
        printUsage(args[0]);
        std.process.exit(1);
    };
    if (port == 0) {
        std.debug.print("Invalid SSH port: 0\n", .{});
        std.process.exit(1);
    }

    var agent_forwarding = false;
    var idfile: ?[]const u8 = null;
    var selected_host_key_mode: ?HostKeyMode = null;
    var known_hosts_path_opt: ?[]const u8 = null;

    var arg_i: usize = 3;
    while (arg_i < args.len) : (arg_i += 1) {
        const arg = args[arg_i];
        if (std.mem.eql(u8, arg, "-A") or std.mem.eql(u8, arg, "--agent-forward")) {
            agent_forwarding = true;
        } else if (std.mem.eql(u8, arg, "--host-key-mode")) {
            arg_i += 1;
            if (arg_i >= args.len) {
                std.debug.print("--host-key-mode requires a value\n", .{});
                printUsage(args[0]);
                std.process.exit(1);
            }
            const mode = parseHostKeyMode(args[arg_i]) catch {
                std.debug.print("Invalid host key mode: {s}\n", .{args[arg_i]});
                printUsage(args[0]);
                std.process.exit(1);
            };
            selectHostKeyMode(&selected_host_key_mode, mode) catch {
                std.debug.print("Conflicting host key modes\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.startsWith(u8, arg, "--host-key-mode=")) {
            const value = arg["--host-key-mode=".len..];
            const mode = parseHostKeyMode(value) catch {
                std.debug.print("Invalid host key mode: {s}\n", .{value});
                printUsage(args[0]);
                std.process.exit(1);
            };
            selectHostKeyMode(&selected_host_key_mode, mode) catch {
                std.debug.print("Conflicting host key modes\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--strict-host-key-checking") or
            std.mem.eql(u8, arg, "--strict"))
        {
            selectHostKeyMode(&selected_host_key_mode, .strict) catch {
                std.debug.print("Conflicting host key modes\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--accept-new")) {
            selectHostKeyMode(&selected_host_key_mode, .accept_new) catch {
                std.debug.print("Conflicting host key modes\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--insecure-demo") or
            std.mem.eql(u8, arg, "--insecure"))
        {
            selectHostKeyMode(&selected_host_key_mode, .insecure_demo) catch {
                std.debug.print("Conflicting host key modes\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--known-hosts")) {
            arg_i += 1;
            if (arg_i >= args.len or args[arg_i].len == 0) {
                std.debug.print("--known-hosts requires a path\n", .{});
                printUsage(args[0]);
                std.process.exit(1);
            }
            if (known_hosts_path_opt != null) {
                std.debug.print("--known-hosts may only be specified once\n", .{});
                std.process.exit(1);
            }
            known_hosts_path_opt = args[arg_i];
        } else if (std.mem.startsWith(u8, arg, "--known-hosts=")) {
            const path = arg["--known-hosts=".len..];
            if (path.len == 0 or known_hosts_path_opt != null) {
                std.debug.print("--known-hosts requires one non-empty path\n", .{});
                std.process.exit(1);
            }
            known_hosts_path_opt = path;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Unknown option: {s}\n", .{arg});
            printUsage(args[0]);
            std.process.exit(1);
        } else if (idfile == null) {
            idfile = arg;
        } else {
            printUsage(args[0]);
            std.process.exit(1);
        }
    }

    const host_key_mode = selected_host_key_mode orelse .strict;
    const at_index = std.mem.lastIndexOfScalar(u8, user_host, '@') orelse {
        std.debug.print("Bad username@host: {s}\n", .{user_host});
        std.process.exit(1);
    };
    if (at_index == 0 or at_index + 1 == user_host.len) {
        std.debug.print("Bad username@host: {s}\n", .{user_host});
        std.process.exit(1);
    }
    const user = user_host[0..at_index];
    const host = user_host[at_index + 1 ..];

    var endpoint_buffer: [known_hosts.max_endpoint_length]u8 = undefined;
    const endpoint = known_hosts.formatEndpoint(&endpoint_buffer, host, port) catch |err| {
        std.debug.print("Invalid SSH endpoint {s}:{d}: {any}\n", .{ host, port, err });
        std.process.exit(1);
    };

    const using_default_known_hosts = host_key_mode != .insecure_demo and
        known_hosts_path_opt == null;
    const known_hosts_path: ?[]const u8 = if (host_key_mode == .insecure_demo)
        known_hosts_path_opt
    else if (known_hosts_path_opt) |path|
        path
    else if (init.environ_map.get("HOME")) |home|
        try std.fmt.allocPrint(allocator, "{s}/.ssh/known_hosts", .{home})
    else {
        std.debug.print(
            "Cannot determine known_hosts path because HOME is unset; use --known-hosts <path>\n",
            .{},
        );
        std.process.exit(1);
    };

    if (using_default_known_hosts and host_key_mode == .accept_new) {
        const home = init.environ_map.get("HOME").?;
        const ssh_directory = try std.fmt.allocPrint(allocator, "{s}/.ssh", .{home});
        known_hosts.ensureDefaultSshDirectory(init.io, ssh_directory) catch |err| {
            std.debug.print(
                "Cannot safely create the default SSH directory {s}: {any}\n",
                .{ ssh_directory, err },
            );
            std.process.exit(1);
        };
    }

    if (host_key_mode == .insecure_demo) {
        std.debug.print(
            \\
            \\*** WARNING: INSECURE DEMO MODE ENABLED ***
            \\Host keys for {s} will not be verified. This is vulnerable to machine-in-the-middle attacks.
            \\
            \\
        , .{endpoint});
    }

    const agent_sock_path = if (agent_forwarding)
        init.environ_map.get("SSH_AUTH_SOCK") orelse {
            std.debug.print("Agent forwarding requested but SSH_AUTH_SOCK is not set\n", .{});
            std.process.exit(1);
        }
    else
        null;

    {
        {
            var stream = connectTcp(init.io, host, port) catch |err| {
                switch (err) {
                    error.ConnectionRefused => std.debug.print("ConnectionRefused\n", .{}),
                    else => std.debug.print("{any}\n", .{err}),
                }
                return;
            };
            defer stream.close(init.io);

            // make a reasonable prng
            var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
            try init.io.randomSecure(&seed);
            var prng = std.Random.DefaultCsprng.init(seed);

            var sshz = try SshzClient.init(prng.random(), user, allocator);
            defer sshz.deinit();
            if (agent_forwarding) {
                try sshz.enableAgentForwarding();
            }

            defer raw_mode_stop();

            var iobuf: [8]u8 = undefined; // could be any size
            var agent_sockets: [MaxAgentSockets]?AgentSocket = .{null} ** MaxAgentSockets;
            defer closeAllAgentSockets(&agent_sockets);
            var quit = false;
            var connected = false;
            var exit_code: u8 = 0;
            const stdin_fd = std.c.STDIN_FILENO;

            outer: while (!quit) {
                const ev = sshz.getNextEvent() catch |err| switch (err) {
                    error.NotReady => {
                        try init.io.sleep(.fromNanoseconds(1 * std.time.ns_per_ms), .awake);
                        continue :outer;
                    },
                    else => return err,
                };
                switch (ev) {
                    .Event => |eventCode| {
                        switch (eventCode) {
                            .ServerIdentification => {
                                try sshz.clearEvent(eventCode);
                            },
                            .AuthMethodStarted => |method| {
                                std.debug.print("Trying authentication method: {s}\n", .{method.name()});
                                try sshz.clearEvent(eventCode);
                            },
                            .Connected => {
                                std.debug.print("Connected!\n", .{});
                                connected = true;
                                try sshz.clearEvent(eventCode);
                                try raw_mode_start();
                            },
                            .RxData => |channel_data| {
                                try writeAllFd(std.c.STDOUT_FILENO, channel_data.data);
                                try sshz.clearEvent(eventCode);
                            },
                            .RxExtendedData => |ext| {
                                _ = ext;
                                try sshz.clearEvent(eventCode);
                            },
                            .Banner => |banner| {
                                std.debug.print("{s}\n", .{banner});
                                try sshz.clearEvent(eventCode);
                            },
                            .EndSession => |reason| {
                                switch (reason) {
                                    .AuthFailure => |failure| {
                                        std.debug.print(
                                            "AuthFailure: stage {d} after {s} (partial_success={any})\n",
                                            .{ failure.auth_stage, failure.attempted_method.name(), failure.partial_success },
                                        );
                                        for (failure.supportedMethods()) |method| {
                                            std.debug.print("  server method: {s}\n", .{method.name()});
                                        }
                                        exit_code = 1;
                                    },
                                    .HostKeyRejected => {
                                        std.debug.print("Host key rejected; authentication was not attempted.\n", .{});
                                        exit_code = 1;
                                    },
                                    else => std.debug.print("Session ended: {any}\n", .{reason}),
                                }
                                quit = true;
                                continue :outer;
                            },
                            .CheckHostKey => |keydata| {
                                var fingerprint_buf: [44]u8 = undefined;
                                const padded_fingerprint = keydata.fingerprintStr(&fingerprint_buf);
                                const fingerprint = std.mem.trimEnd(u8, padded_fingerprint, "=");
                                const raw_key = keydata.raw_key orelse {
                                    std.debug.print(
                                        "HOST KEY VERIFICATION FAILED for {s}: the server supplied no host key blob\n",
                                        .{endpoint},
                                    );
                                    try sshz.rejectHostKey();
                                    exit_code = 1;
                                    quit = true;
                                    continue :outer;
                                };

                                switch (host_key_mode) {
                                    .strict => {
                                        const result = known_hosts.checkFile(
                                            init.io,
                                            allocator,
                                            known_hosts_path.?,
                                            endpoint,
                                            raw_key,
                                        ) catch |err| {
                                            std.debug.print(
                                                \\HOST KEY VERIFICATION FAILED for {s}
                                                \\known_hosts file: {s}
                                                \\Presented fingerprint: SHA256:{s}
                                                \\Could not safely parse or read known_hosts: {any}
                                                \\
                                            , .{ endpoint, known_hosts_path.?, fingerprint, err });
                                            try sshz.rejectHostKey();
                                            exit_code = 1;
                                            quit = true;
                                            continue :outer;
                                        };
                                        switch (result) {
                                            .match => {},
                                            .unknown => {
                                                printHostKeyUnknown(endpoint, known_hosts_path.?, fingerprint);
                                                try sshz.rejectHostKey();
                                                exit_code = 1;
                                                quit = true;
                                                continue :outer;
                                            },
                                            .changed => {
                                                printHostKeyMismatch(endpoint, known_hosts_path.?, fingerprint);
                                                try sshz.rejectHostKey();
                                                exit_code = 1;
                                                quit = true;
                                                continue :outer;
                                            },
                                        }
                                    },
                                    .accept_new => {
                                        const result = known_hosts.acceptNew(
                                            init.io,
                                            allocator,
                                            known_hosts_path.?,
                                            endpoint,
                                            raw_key,
                                        ) catch |err| {
                                            if (err == error.HostKeyChanged) {
                                                printHostKeyMismatch(endpoint, known_hosts_path.?, fingerprint);
                                            } else {
                                                std.debug.print(
                                                    \\HOST KEY VERIFICATION FAILED for {s}
                                                    \\known_hosts file: {s}
                                                    \\Presented fingerprint: SHA256:{s}
                                                    \\Could not safely update known_hosts: {any}
                                                    \\
                                                , .{ endpoint, known_hosts_path.?, fingerprint, err });
                                            }
                                            try sshz.rejectHostKey();
                                            exit_code = 1;
                                            quit = true;
                                            continue :outer;
                                        };
                                        if (result == .added) {
                                            std.debug.print(
                                                "Added host key for {s} to {s} (SHA256:{s})\n",
                                                .{ endpoint, known_hosts_path.?, fingerprint },
                                            );
                                        }
                                    },
                                    .insecure_demo => {
                                        std.debug.print(
                                            "WARNING: insecure demo mode accepted the unverified host key for {s} (SHA256:{s})\n",
                                            .{ endpoint, fingerprint },
                                        );
                                    },
                                }
                                try sshz.acceptHostKey();
                            },
                            .GetPrivateKey => {
                                if (idfile) |path| {
                                    const keydata_ascii = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1024)) catch {
                                        std.debug.print("Failed to open idfile {s}\n", .{path});
                                        std.process.exit(1);
                                    };
                                    try sshz.setPrivateKey(keydata_ascii);
                                    allocator.free(keydata_ascii);
                                }
                                try sshz.clearEvent(eventCode);
                            },
                            .GetKeyPassphrase => {
                                var password_buf: [128]u8 = undefined;
                                try sshz.setPrivateKeyPassphrase(try envOrReadPassphrase(init, "SSHZ_KEY_PASSPHRASE", "Password for private key decrypt: ", &password_buf));
                                try sshz.clearEvent(eventCode);
                            },
                            .GetAuthPassphrase => {
                                var password_buf: [128]u8 = undefined;
                                try sshz.setAuthPassphrase(try envOrReadPassphrase(init, "SSHZ_AUTH_PASSWORD", "Password for auth: ", &password_buf));
                                try sshz.clearEvent(eventCode);
                            },
                            .KeyboardInteractive => |prompt| {
                                var password_buf: [128]u8 = undefined;
                                try sshz.session.setKeyboardInteractiveResponse(try envOrReadPassphrase(init, "SSHZ_AUTH_PASSWORD", prompt.prompt, &password_buf));
                                try sshz.clearEvent(eventCode);
                            },
                            .ChannelOpened,
                            .ChannelOpenFailure,
                            .ChannelEof,
                            .ChannelClosed,
                            .TcpipForwardSuccess,
                            .TcpipForwardFailure,
                            .CancelTcpipForwardSuccess,
                            .CancelTcpipForwardFailure,
                            => {
                                try sshz.clearEvent(eventCode);
                            },
                            .ChannelOpenRequest => |request| {
                                try sshz.rejectChannelOpen(
                                    request.channel,
                                    SshOpenFailureReason.AdministrativelyProhibited,
                                    "unsupported channel open",
                                );
                            },
                            .AgentChannelOpen => |channel| {
                                try sshz.clearEvent(eventCode);
                                addAgentSocket(&agent_sockets, channel, agent_sock_path.?) catch |err| {
                                    std.debug.print("Failed to connect SSH_AUTH_SOCK for agent channel {d}: {any}\n", .{ channel, err });
                                    try sshz.sendChannelEof(channel);
                                };
                            },
                            .AgentData => |agent_data| {
                                var close_channel = false;
                                if (findAgentSocket(&agent_sockets, agent_data.channel)) |agent| {
                                    writeAllFd(agent.fd, agent_data.data) catch |err| {
                                        std.debug.print("Failed to write agent data for channel {d}: {any}\n", .{ agent_data.channel, err });
                                        closeAgentSocket(&agent_sockets, agent_data.channel);
                                        close_channel = true;
                                    };
                                } else {
                                    close_channel = true;
                                }
                                try sshz.clearEvent(eventCode);
                                if (close_channel) try sshz.sendChannelEof(agent_data.channel);
                            },
                            .AgentChannelClosed => |channel| {
                                closeAgentSocket(&agent_sockets, channel);
                                try sshz.clearEvent(eventCode);
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

                        var fds: [2 + MaxAgentSockets]std.posix.pollfd = undefined;
                        fds[0] = .{
                            .fd = stream.socket.handle,
                            .events = pollevts,
                            .revents = undefined,
                        };
                        fds[1] = .{
                            .fd = stdin_fd,
                            .events = if (connected) std.posix.POLL.IN else 0,
                            .revents = undefined,
                        };
                        var fd_count: usize = 2;
                        for (agent_sockets) |agent_opt| {
                            if (agent_opt) |agent| {
                                fds[fd_count] = .{
                                    .fd = agent.fd,
                                    .events = std.posix.POLL.IN,
                                    .revents = undefined,
                                };
                                fd_count += 1;
                            }
                        }

                        const ready = std.posix.poll(fds[0..fd_count], 1000) catch 0;
                        if (ready > 0) {
                            if (fds[0].revents & std.posix.POLL.IN > 0) { // socket is readable
                                var bytes_to_read = consume_len;
                                if (bytes_to_read > iobuf.len) {
                                    bytes_to_read = iobuf.len;
                                }
                                const nbytes = try readFd(stream.socket.handle, iobuf[0..bytes_to_read]);
                                if (nbytes > 0) {
                                    try sshz.write(iobuf[0..nbytes]);
                                    continue :outer;
                                }
                            }
                            if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                                const towrite = try sshz.peek(4);
                                const bytes_written = try writeFd(stream.socket.handle, towrite);
                                try sshz.consumed(bytes_written);
                                continue :outer;
                            }
                            if (fds[1].revents & std.posix.POLL.IN > 0) { // keyboard data in
                                const buf = try sshz.getChannelWriteBuffer(0);
                                if (buf.len > 0) {
                                    const count = readFd(stdin_fd, buf) catch 0;
                                    if (count > 0) {
                                        try sshz.channelWriteComplete(0, count);
                                        continue :outer;
                                    }
                                }
                            }
                            var poll_idx: usize = 2;
                            for (&agent_sockets) |*agent_slot| {
                                if (agent_slot.*) |agent| {
                                    const revents = fds[poll_idx].revents;
                                    poll_idx += 1;
                                    if (revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR) > 0) {
                                        const buf = try sshz.getChannelWriteBuffer(agent.channel);
                                        if (buf.len > 0) {
                                            const count = readFd(agent.fd, buf) catch |err| {
                                                std.debug.print("Failed to read SSH_AUTH_SOCK for channel {d}: {any}\n", .{ agent.channel, err });
                                                closeAgentSocket(&agent_sockets, agent.channel);
                                                try sshz.sendChannelEof(agent.channel);
                                                continue;
                                            };
                                            if (count > 0) {
                                                try sshz.channelWriteComplete(agent.channel, count);
                                                continue :outer;
                                            }
                                            closeAgentSocket(&agent_sockets, agent.channel);
                                            try sshz.sendChannelEof(agent.channel);
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }

            if (exit_code != 0) {
                std.process.exit(exit_code);
            }
        }
    }
}
