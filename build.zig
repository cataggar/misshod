const std = @import("std");
const builtin = @import("builtin");

comptime {
    const required_zig = "0.16.0";
    const current_zig = builtin.zig_version;
    const min_zig = std.SemanticVersion.parse(required_zig) catch unreachable;
    if (current_zig.order(min_zig) == .lt) {
        const error_message = "Your version of zig is too old\nDownload {} or newer";
        @compileError(std.fmt.comptimePrint(error_message, .{min_zig}));
    }
}

/// zlib is built from source rather than taken from the system.
///
/// `zlib@openssh.com` compression is not optional -- `protocol.zig` reaches
/// `zlib.h` unconditionally -- so a system library made the whole package
/// unbuildable anywhere one is not installed and discoverable, Windows
/// included. The dependency carries zlib's own sources and compiles them for
/// whatever target is being built, so the same `zig build` works on every
/// host, and every module here links the one static artifact.
fn linkZlib(b: *std.Build, mod: *std.Build.Module) void {
    const dep = b.dependency("zlib", .{
        .target = mod.resolved_target.?,
        .optimize = mod.optimize.?,
    });
    mod.linkLibrary(dep.artifact("z"));
}

/// How much the library is allowed to print.
///
/// `off` by default because an application that links sshz owns its own
/// stderr -- and, if it draws a terminal UI, its own screen. `sshz` and
/// `sshzd` ask for `info`.
pub const TraceLevel = enum { off, info, debug };

/// What a build gets when it does not ask. Named so `trace_off_test` can
/// assert on it: changing this to anything but `off` fails the suite.
const default_trace_level: TraceLevel = .off;
const default_channel_capacity: u8 = 4;

/// What `-Dversion` reports when nobody passes one.
///
/// The tag is the source of truth for a release: a tagged build passes
/// `-Dversion=${GITHUB_REF_NAME#v}` and stamps its own tag. This fallback
/// tracks the version declared in `build.zig.zon` so an untagged build
/// still reports something truthful.
const default_version = "0.2.1";

/// Emitted as a name rather than the enum itself so `util.zig` keeps one
/// definition of the level and maps onto it explicitly.
fn addTraceLevel(options: *std.Build.Step.Options, level: TraceLevel) void {
    options.addOption([]const u8, "trace_level", @tagName(level));
}

fn addSshzOptions(
    options: *std.Build.Step.Options,
    unsafe_secret_tracing: bool,
    trace_level: TraceLevel,
    channel_capacity: u8,
    version: []const u8,
) void {
    options.addOption(bool, "unsafe_secret_tracing", unsafe_secret_tracing);
    addTraceLevel(options, trace_level);
    options.addOption(u8, "channel_capacity", channel_capacity);
    options.addOption([]const u8, "version", version);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const trace_level = b.option(
        TraceLevel,
        "trace",
        "How much sshz prints to stderr (default: off)",
    ) orelse default_trace_level;

    // UNSAFE: This may print plaintext packets, private keys, shared secrets,
    // and derived encryption/MAC keys. Never enable it in production or CI.
    const unsafe_secret_tracing = b.option(
        bool,
        "unsafe-secret-tracing",
        "UNSAFE: allow diagnostic dumps of plaintext and cryptographic secrets",
    ) orelse false;
    const channel_capacity = b.option(
        u8,
        "channel_capacity",
        "Compile-time channel-table capacity (default: 4)",
    ) orelse default_channel_capacity;
    const version = b.option(
        []const u8,
        "version",
        "Version string reported by the library (release builds pass the tag)",
    ) orelse default_version;
    const options = b.addOptions();
    addSshzOptions(options, unsafe_secret_tracing, trace_level, channel_capacity, version);

    const mod = b.addModule("sshz", .{
        .root_source_file = b.path("src/sshz.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addOptions("sshz_build_options", options);
    linkZlib(b, mod);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addOptions("sshz_build_options", options);
    linkZlib(b, test_mod);

    const lib_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);

    const safe_trace_options = b.addOptions();
    addSshzOptions(safe_trace_options, false, trace_level, channel_capacity, version);
    const safe_trace_test_mod = b.createModule(.{
        .root_source_file = b.path("src/trace_gate_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    safe_trace_test_mod.addOptions("sshz_build_options", safe_trace_options);
    const safe_trace_tests = b.addTest(.{
        .root_module = safe_trace_test_mod,
    });
    const run_safe_trace_tests = b.addRunArtifact(safe_trace_tests);

    // Built with the options a dependent gets, not the ones this invocation
    // was given, so `zig build test -Dtrace=info` does not silently excuse
    // the default from staying quiet.
    const default_trace_options = b.addOptions();
    addSshzOptions(default_trace_options, false, default_trace_level, default_channel_capacity, version);
    const trace_off_test_mod = b.createModule(.{
        .root_source_file = b.path("src/trace_off_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    trace_off_test_mod.addOptions("sshz_build_options", default_trace_options);
    const trace_off_tests = b.addTest(.{
        .root_module = trace_off_test_mod,
    });
    const run_trace_off_tests = b.addRunArtifact(trace_off_tests);

    const configured_capacity_options = b.addOptions();
    addSshzOptions(configured_capacity_options, false, default_trace_level, 8, version);
    const configured_capacity_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configured_capacity_test_mod.addOptions("sshz_build_options", configured_capacity_options);
    linkZlib(b, configured_capacity_test_mod);
    const configured_capacity_tests = b.addTest(.{
        .root_module = configured_capacity_test_mod,
        .filters = &.{"configured channel capacity supports concurrent tunnel channels"},
    });
    const run_configured_capacity_tests = b.addRunArtifact(configured_capacity_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_safe_trace_tests.step);
    test_step.dependOn(&run_trace_off_tests.step);
    test_step.dependOn(&run_configured_capacity_tests.step);

    const production_client_mod = b.createModule(.{
        .root_source_file = b.path("examples/production/client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    production_client_mod.addImport("sshz", mod);
    production_client_mod.addAnonymousImport("production_test_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    linkZlib(b, production_client_mod);
    const production_client = b.addExecutable(.{
        .name = "sshz-production-client-example",
        .root_module = production_client_mod,
    });
    const production_client_tests = b.addTest(.{
        .root_module = production_client_mod,
    });
    const run_production_client_tests = b.addRunArtifact(production_client_tests);

    const production_server_mod = b.createModule(.{
        .root_source_file = b.path("examples/production/server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    production_server_mod.addImport("sshz", mod);
    production_server_mod.addAnonymousImport("production_test_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    linkZlib(b, production_server_mod);
    const production_server = b.addExecutable(.{
        .name = "sshz-production-server-example",
        .root_module = production_server_mod,
    });
    const production_server_tests = b.addTest(.{
        .root_module = production_server_mod,
    });
    const run_production_server_tests = b.addRunArtifact(production_server_tests);

    const production_examples_step = b.step(
        "production-examples",
        "Compile-check production client and server integration examples",
    );
    production_examples_step.dependOn(&production_client.step);
    production_examples_step.dependOn(&production_server.step);
    production_examples_step.dependOn(&run_production_client_tests.step);
    production_examples_step.dependOn(&run_production_server_tests.step);

    const malformed_mod = b.createModule(.{
        .root_source_file = b.path("test/malformed.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    malformed_mod.addImport("sshz", mod);
    linkZlib(b, malformed_mod);
    const malformed_tests = b.addTest(.{
        .root_module = malformed_mod,
    });
    const run_malformed_tests = b.addRunArtifact(malformed_tests);
    const malformed_step = b.step("malformed", "Run the bounded deterministic malformed-input corpus");
    malformed_step.dependOn(&run_malformed_tests.step);

    const stress_mod = b.createModule(.{
        .root_source_file = b.path("test/stress/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    stress_mod.addImport("sshz", mod);
    stress_mod.addAnonymousImport("stress_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    linkZlib(b, stress_mod);
    const stress_exe = b.addExecutable(.{
        .name = "sshz-stress",
        .root_module = stress_mod,
    });

    const run_stress = b.addRunArtifact(stress_exe);
    if (b.args) |args| run_stress.addArgs(args);
    const stress_step = b.step("stress", "Run deterministic in-process stress acceptance");
    stress_step.dependOn(&run_stress.step);

    const soak_cmd = b.addSystemCommand(&.{ "bash", "test/stress/soak.sh" });
    soak_cmd.addArtifactArg(stress_exe);
    if (b.args) |args| soak_cmd.addArgs(args);
    const soak_step = b.step("soak", "Run duration/seed/peer-selected soak coverage");
    soak_step.dependOn(&soak_cmd.step);

    const interop_cmd = b.addSystemCommand(&.{ "bash", "interop/run.sh" });
    interop_cmd.step.dependOn(&run_lib_tests.step);

    const interop_step = b.step("interop", "Run OpenSSH/libssh interoperability tests");
    interop_step.dependOn(&interop_cmd.step);
}
