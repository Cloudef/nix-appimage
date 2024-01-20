const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.runtime);
const OsRelease = @import("OsRelease.zig");
const setenv = @import("setenv.zig").setenv;

pub const std_options = struct {
    pub const log_level = .debug;
};

// Only care about non-FHS distros
const Distro = enum {
    nixos,
    guix,
    gobolinux,
    other,
};

// https://old.reddit.com/r/linuxquestions/comments/62g28n/deleted_by_user/dfmjht6/
fn detectDistro() Distro {
    if (std.os.getenv("DISTRO_OVERRIDE")) |env| {
        return std.meta.stringToEnum(Distro, env) orelse .other;
    }

    // This usually works, anything else is a fallback
    if (OsRelease.init()) |distro| {
        if (distro.id) |id| {
            log.info("detected linux distribution: {s}", .{distro.pretty_name orelse distro.name orelse id});
            if (std.meta.stringToEnum(Distro, id)) |d| return d;
            return .other;
        }
    }

    if (std.fs.accessAbsolute("/run/current-system/nixos-version", .{ .mode = .read_only })) {
        log.info("detected linux distribution: NixOS", .{});
        return .nixos;
    } else |_| {}

    if (std.fs.accessAbsolute("/etc/GoboLinuxVersion", .{ .mode = .read_only })) {
        log.info("detected linux distribution: GoboLinux", .{});
        return .gobolinux;
    } else |_| {}

    log.warn("unknown linux distribution", .{});
    return .other;
}

const StoreIterator = struct {
    iter: std.mem.TokenIterator(u8, .scalar),

    pub fn init(store: []const u8) @This() {
        return .{ .iter = std.mem.tokenizeScalar(u8, store, '\n') };
    }

    pub fn findNext(self: *@This(), needle: []const u8) ?[]const u8 {
        while (self.iter.next()) |path| if (std.mem.count(u8, path, needle) > 0) return path;
        return null;
    }

    pub fn get(allocator: std.mem.Allocator, store: []const u8, needle: []const u8, component: []const u8) ![]const u8 {
        var iter = StoreIterator.init(store);
        var tmp: std.ArrayListUnmanaged(u8) = .{};
        defer tmp.deinit(allocator);
        while (iter.findNext(needle)) |path| {
            try tmp.resize(allocator, 0);
            try tmp.writer(allocator).print("{s}/{s}", .{ path, component });
            if (std.fs.accessAbsolute(path, .{ .mode = .read_only })) {
                return try tmp.toOwnedSlice(allocator);
            } else |_| {}
        }
        log.err("could not find {s} from the store", .{needle});
        return error.StoreGetFailed;
    }
};

const SearchPath = struct {
    bytes: std.ArrayListUnmanaged(u8) = .{},

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.bytes.deinit(allocator);
    }

    pub fn append(self: *@This(), allocator: std.mem.Allocator, path: []const u8) !bool {
        if (self.bytes.items.len > 0) {
            if (std.mem.count(u8, self.bytes.items, path) > 0) return true;
            if (std.meta.isError(std.fs.accessAbsolute(path, .{ .mode = .read_only }))) return false;
            try self.bytes.append(allocator, ':');
        }
        try self.bytes.appendSlice(allocator, path);
        return true;
    }

    pub fn appendWithPathComponent(self: *@This(), allocator: std.mem.Allocator, path: []const u8, component: []const u8) !bool {
        const buf = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path, component });
        defer allocator.free(buf);
        return try self.append(allocator, buf);
    }
};

const SonameIterator = struct {
    iter: std.mem.TokenIterator(u8, .scalar),

    pub fn init(sonames: []const u8) @This() {
        return .{ .iter = std.mem.tokenizeScalar(u8, sonames, 0) };
    }

    pub fn next(self: *@This(), as_base: bool) ?[]const u8 {
        const ignored: []const []const u8 = &.{
            "libm", "libpthread", "libc", "libdl",
        };

        while (self.iter.next()) |soname| {
            var split = std.mem.splitScalar(u8, soname, '.');
            const base = split.first();

            if (std.mem.count(u8, base, "ld-linux-") > 0) {
                continue;
            }

            const is_ignored = blk: {
                inline for (ignored) |ignore| {
                    if (std.mem.eql(u8, base, ignore)) break :blk true;
                }
                break :blk false;
            };

            if (is_ignored) {
                continue;
            }

            return if (as_base) base else soname;
        }

        return null;
    }
};

fn runCmd(allocator: std.mem.Allocator, cmd: []const u8) ![]const u8 {
    const rr = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "sh", "-c", cmd },
        .max_output_bytes = std.math.maxInt(usize) / 2,
    }) catch |err| {
        log.err("failed to exec: {s}", .{cmd});
        return err;
    };
    errdefer allocator.free(rr.stdout);
    defer allocator.free(rr.stderr);
    switch (rr.term) {
        .Exited => |code| {
            if (code != 0) {
                log.err("execution unsuccesful ({d}): {s}", .{ code, cmd });
                return error.RunCmdFailed;
            }
        },
        .Signal, .Unknown, .Stopped => {
            log.err("execution ended unexpectedly: {s}", .{cmd});
            return error.RunCmdFailed;
        },
    }
    return rr.stdout;
}

fn getSonames(allocator: std.mem.Allocator, grep: []const u8, path: []const u8) ![]const u8 {
    // TODO: do this without grep
    const cmd = try std.fmt.allocPrint(allocator, "{s} -a --null-data -o '.*[.]so[.0-9]*$' {s}", .{ grep, path });
    defer allocator.free(cmd);
    return runCmd(allocator, cmd);
}

fn setupLinux(allocator: std.mem.Allocator, bin: []const u8) !void {
    var ld_library_path: SearchPath = .{};
    defer ld_library_path.deinit(allocator);

    if (std.os.getenv("LD_LIBRARY_PATH")) |path0| if (path0.len > 0) {
        _ = try ld_library_path.append(allocator, path0);
    };
    const orig_ld_path_len = ld_library_path.bytes.items.len;

    // NixOS, Guix and GoboLinux are to my knowledge the only non-FHS Linux distros
    // However GoboLinux apparently has FHS compatibility, so it probably works OOB?
    switch (detectDistro()) {
        .nixos => {
            log.info("setting up nixos runtime ...", .{});

            // packages that match a soname don't have to be included
            const map = std.comptime_string_map.ComptimeStringMap([]const u8, .{
                .{ "libvulkan", "vulkan-loader" },
                .{ "libGL", "libglvnd" },
                .{ "libEGL", "libglvnd" },
                .{ "libGLdispatch", "libglvnd" },
                .{ "libGLES_CM", "libglvnd" },
                .{ "libGLESv1_CM", "libglvnd" },
                .{ "libGLESv2", "libglvnd" },
                .{ "libGLX", "libglvnd" },
                .{ "libOSMesa", "mesa" },
                .{ "libOpenGL", "libglvnd" },
                .{ "libX11-xcb", "libX11" },
                .{ "libwayland-client", "wayland" },
                .{ "libwayland-cursor", "wayland" },
                .{ "libwayland-server", "wayland" },
                .{ "libwayland-egl", "wayland" },
                .{ "libdecor-0", "libdecor" },
                .{ "libgamemode", "gamemode" },
                .{ "libasound", "alsa-lib" },
                .{ "libjack", "jack-libs:pipewire:libjack2" },
                .{ "pipewire", "pipewire" },
                .{ "pulse", "libpulseaudio:pulseaudio" },
            });

            const store = try runCmd(allocator, "/run/current-system/sw/bin/nix-store -q --requisites /run/current-system");
            defer allocator.free(store);

            const grep = try StoreIterator.get(allocator, store, "-gnugrep-", "bin/grep");
            defer allocator.free(grep);

            const sonames = try getSonames(allocator, grep, bin);
            defer allocator.free(sonames);

            var needle: std.ArrayListUnmanaged(u8) = .{};
            defer needle.deinit(allocator);

            var so_iter = SonameIterator.init(sonames);
            while (so_iter.next(true)) |soname| {
                const pkgs = std.fs.path.basename(map.get(soname) orelse soname);
                var found_any = false;
                var pkgs_iter = SearchPathIterator.initPath(pkgs);
                while (pkgs_iter.next()) |pkg| {
                    try needle.resize(allocator, 0);
                    try needle.writer(allocator).print("-{s}-", .{pkg});
                    var iter = StoreIterator.init(store);
                    while (iter.findNext(needle.items)) |path| {
                        if (try ld_library_path.appendWithPathComponent(allocator, path, "lib")) {
                            found_any = true;
                        }
                    }
                }

                if (!found_any) {
                    log.warn("missing library: {s}", .{soname});
                }
            }
        },
        .guix => {
            log.info("setting up guix runtime ...", .{});

            // I'm not sure if this is okay, but guix seems to not be so opposed to global env like nix is
            // And this path at least in guix live cd has mostly everything neccessary
            _ = try ld_library_path.append(allocator, "/run/current-system/profile/lib");

            const sonames = try getSonames(allocator, "/run/current-system/profile/bin/grep", bin);
            defer allocator.free(sonames);

            var needle: std.ArrayListUnmanaged(u8) = .{};
            defer needle.deinit(allocator);

            // loop the sonames though to let guix user know if there's any missing libraries
            var so_iter = SonameIterator.init(sonames);
            while (so_iter.next(false)) |soname| {
                try needle.resize(allocator, 0);
                try needle.writer(allocator).print("/run/current-system/profile/lib/{s}", .{soname});
                if (std.fs.accessAbsolute(needle.items, .{ .mode = .read_only })) {
                    continue;
                } else |_| {}
                log.warn("missing library: {s}", .{soname});
            }
        },
        .gobolinux, .other => {},
    }

    if (ld_library_path.bytes.items.len != orig_ld_path_len) {
        try setenv("LD_LIBRARY_PATH", ld_library_path.bytes.items);
    }
}

fn setupRuntime(allocator: std.mem.Allocator, bin: []const u8) void {
    switch (builtin.os.tag) {
        .linux => setupLinux(allocator, bin) catch |err| {
            log.warn("{}: runtime is incomplete and the program may not function properly", .{err});
        },
        else => {
            log.warn("unknown os, no idea what to do", .{});
        },
    }
}

fn writeTo(path: []const u8, comptime format: []const u8, args: anytype) !void {
    var f = std.fs.openFileAbsolute(path, .{ .mode = .write_only }) catch |err| {
        log.err("write failed to: {s}", .{path});
        return err;
    };
    defer f.close();
    var bounded: std.BoundedArray(u8, 1024) = .{};
    try bounded.writer().print(format, args);
    try f.writer().writeAll(bounded.constSlice());
}

fn oserr(rc: usize) !void {
    return switch (std.os.errno(rc)) {
        .SUCCESS => {},
        else => |e| std.os.unexpectedErrno(e),
    };
}

fn mount(special: [:0]const u8, dir: [:0]const u8, fstype: [:0]const u8, flags: u32, data: usize) !void {
    oserr(std.os.linux.mount(special, dir, fstype, flags, data)) catch |err| {
        log.err("mount {s} {s} -> {s}", .{ special, dir, fstype });
        return err;
    };
}

fn replicatePath(allocator: std.mem.Allocator, src: [:0]const u8, dst: [:0]const u8) !void {
    if (std.fs.accessAbsolute(dst, .{ .mode = .read_only })) {
        log.warn("destination already exists, skipping: {s}", .{dst});
        return;
    } else |_| {}

    const stat = std.fs.cwd().statFile(src) catch {
        log.warn("failed to stat, skipping: {s}", .{src});
        return;
    };

    std.fs.cwd().makePath(std.fs.path.dirname(dst).?) catch {};

    switch (stat.kind) {
        .directory => {
            std.fs.makeDirAbsolute(dst) catch |err| {
                log.err("failed to create directory: {s}", .{dst});
                return err;
            };
            try mount(src, dst, "none", std.os.linux.MS.BIND | std.os.linux.MS.REC, 0);
        },
        .file => {
            var f = std.fs.createFileAbsolute(dst, .{}) catch |err| {
                log.err("failed to create file: {s}", .{dst});
                return err;
            };
            f.close();
            try mount(src, dst, "none", std.os.linux.MS.BIND | std.os.linux.MS.REC, 0);
        },
        .sym_link => {
            var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpathAlloc(allocator, try std.fs.readLinkAbsolute(src, &buf));
            defer allocator.free(path);
            const sstat = std.fs.cwd().statFile(path) catch {
                log.warn("failed to stat, skipping: {s}", .{path});
                return;
            };
            try std.fs.symLinkAbsolute(path, dst, .{ .is_directory = sstat.kind == .directory });
        },
        else => {
            log.warn("do not know how to replicate {s}: {s}", .{ @tagName(stat.kind), src });
        },
    }
}

fn replicatePathWithRoots(allocator: std.mem.Allocator, src_root: []const u8, src_base: []const u8, dst_root: []const u8, dst_base: []const u8) !void {
    std.debug.assert(src_root.len > 0 and dst_root.len > 1);
    std.debug.assert(src_root[0] == '/' and dst_root[0] == '/');
    const resolved_src_root = if (src_root.len > 1 or src_root[0] == '/') "" else src_root;
    const src = try std.fmt.allocPrintZ(allocator, "{s}/{s}", .{ resolved_src_root, src_base });
    defer allocator.free(src);
    const dst = try std.fmt.allocPrintZ(allocator, "{s}/{s}", .{ dst_root, dst_base });
    defer allocator.free(dst);
    try replicatePath(allocator, src, dst);
}

fn replicateDir(allocator: std.mem.Allocator, src: []const u8, dst: []const u8, comptime ignored: []const []const u8) !void {
    var dir = std.fs.openDirAbsolute(src, .{ .iterate = true }) catch {
        log.warn("directory does not exist, skipping replication of: {s}", .{src});
        return;
    };
    defer dir.close();
    std.fs.makeDirAbsolute(dst) catch {};

    var iter = dir.iterate();
    while (try iter.next()) |ent| {
        if (std.mem.eql(u8, ent.name, ".") or
            std.mem.eql(u8, ent.name, ".."))
        {
            continue;
        }

        const should_skip: bool = blk: {
            inline for (ignored) |ignore| if (std.mem.eql(u8, ent.name, ignore)) break :blk true;
            break :blk false;
        };

        if (should_skip) {
            continue;
        }

        try replicatePathWithRoots(allocator, src, ent.name, dst, ent.name);
    }
}

const SearchPathIterator = struct {
    paths: std.mem.TokenIterator(u8, .scalar),

    pub fn initEnv(env: []const u8) @This() {
        return .{ .paths = std.mem.tokenizeScalar(u8, std.os.getenv(env) orelse "", ':') };
    }

    pub fn initPath(path: []const u8) @This() {
        return .{ .paths = std.mem.tokenizeScalar(u8, path, ':') };
    }

    pub fn next(self: *@This()) ?[]const u8 {
        return self.paths.next();
    }
};

fn setupNamespace(allocator: std.mem.Allocator, appdir: []const u8) !void {
    const mountroot = try std.fmt.allocPrintZ(allocator, "{s}/mountroot", .{appdir});
    defer allocator.free(mountroot);
    std.fs.makeDirAbsolute(mountroot) catch {};

    const uid = std.os.linux.getuid();
    const gid = std.os.linux.getgid();

    var clonens: usize = std.os.linux.CLONE.NEWNS;
    if (uid != 0) clonens |= std.os.linux.CLONE.NEWUSER;
    if (std.os.linux.unshare(clonens) < 0) {
        return error.UnshareFailed;
    }

    if (uid != 0) {
        // UID/GID Mapping -----------------------------------------------------------

        // see user_namespaces(7)
        // > The data written to uid_map (gid_map) must consist of a single line that
        // > maps the writing process's effective user ID (group ID) in the parent
        // > user namespace to a user ID (group ID) in the user namespace.
        try writeTo("/proc/self/uid_map", "{d} {d} 1", .{ uid, uid });

        // see user_namespaces(7):
        // > In the case of gid_map, use of the setgroups(2) system call must first
        // > be denied by writing "deny" to the /proc/[pid]/setgroups file (see
        // > below) before writing to gid_map.
        try writeTo("/proc/self/setgroups", "deny", .{});
        try writeTo("/proc/self/gid_map", "{d} {d} 1", .{ uid, gid });
    }

    // tmpfs so we don't need to cleanup
    try mount("tmpfs", mountroot, "tmpfs", 0, 0);
    // make unbindable to both prevent event propagation as well as mount explosion
    try mount(mountroot, mountroot, "none", std.os.linux.MS.UNBINDABLE, 0);

    // setup /
    try replicateDir(allocator, "/", mountroot, &.{"nix"});

    // setup nix
    {
        const src = try std.fmt.allocPrintZ(allocator, "{s}/nix/store", .{appdir});
        defer allocator.free(src);
        std.fs.cwd().makePath(src) catch {};
        const dst = try std.fmt.allocPrintZ(allocator, "{s}/nix/store", .{mountroot});
        defer allocator.free(dst);
        std.fs.cwd().makePath(dst) catch {};
        if (std.fs.accessAbsolute("/nix", .{ .mode = .read_only })) {
            const opts = try std.fmt.allocPrintZ(allocator, "lowerdir=/nix/store:{s}", .{src});
            defer allocator.free(opts);
            log.info("/nix exists, mounting {s} as a overlay: {s}", .{ dst, opts });
            try mount("overlay", dst, "overlay", 0, @intFromPtr(opts.ptr));
        } else |_| {
            try mount(src, dst, "none", std.os.linux.MS.BIND | std.os.linux.MS.REC, 0);
        }
    }

    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    try oserr(std.os.linux.chroot(mountroot));
    try std.os.chdir(cwd);
}

fn dynamicLinkerFromPath(allocator: std.mem.Allocator, path: []const u8) !?[]const u8 {
    var f = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        log.err("unable to open: {s}", .{path});
        return err;
    };
    defer f.close();
    const target = try std.zig.system.abiAndDynamicLinkerFromFile(f, builtin.target.cpu, builtin.target.os, &.{}, .{});
    return try allocator.dupe(u8, target.dynamic_linker.get().?);
}

fn parseArgs(allocator: std.mem.Allocator, appdir: []const u8, has_dl: *bool) ![]const []const u8 {
    var args: std.ArrayListUnmanaged([]const u8) = .{};
    defer args.deinit(allocator);

    const exe = blk: {
        const base = try std.fmt.allocPrint(allocator, "{s}/entrypoint", .{appdir});
        var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const link = std.fs.readLinkAbsolute(base, &buf) catch break :blk base;
        allocator.free(base);
        break :blk try std.fmt.allocPrint(allocator, "{s}{s}", .{ appdir, link });
    };

    if (try dynamicLinkerFromPath(allocator, exe)) |dl0| {
        defer allocator.free(dl0);
        if (try dynamicLinkerFromPath(allocator, "/usr/bin/env")) |dl| {
            log.info("dynamic linker: {s}", .{dl});
            try args.append(allocator, dl);
            has_dl.* = true;
        } else {
            log.warn("unable to figure out the dynamic linker, falling back to: {s}", .{dl0});
        }
    }

    try args.append(allocator, exe);
    var iter = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();
    _ = iter.skip();
    while (iter.next()) |arg| try args.append(allocator, try allocator.dupe(u8, arg));
    return try args.toOwnedSlice(allocator);
}

fn run(allocator: std.mem.Allocator) !void {
    const appdir = std.fs.selfExeDirPathAlloc(allocator) catch |err| {
        log.err("failed to locate the appdir", .{});
        return err;
    };
    defer allocator.free(appdir);

    var has_dl: bool = false;
    const args = try parseArgs(allocator, appdir, &has_dl);
    defer {
        for (args) |arg| allocator.free(arg);
        allocator.free(args);
    }

    const exe = if (has_dl) args[1] else args[0];

    {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        setupRuntime(arena.allocator(), exe);
        try setupNamespace(arena.allocator(), appdir);
    }

    if (std.os.getenv("LD_LIBRARY_PATH")) |path0| log.info("LD_LIBRARY_PATH={s}", .{path0});
    log.info("executing: {s}", .{exe});
    std.process.execv(allocator, args) catch {
        log.err("unable to execute: {s}", .{exe});
        return error.ExecFailed;
    };
}

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    run(gpa.allocator()) catch |err| {
        log.err("fatal error: {}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        std.os.exit(127);
    };
}
