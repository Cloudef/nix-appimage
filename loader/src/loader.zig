const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.loader);
const runtime = @import("runtime.zig");
const appimage = @import("appimage.zig");

pub const std_options = struct {
    pub const log_level = .debug;
};

fn dynamicLinkerFromPath(allocator: std.mem.Allocator, path: []const u8) !?[]const u8 {
    var f = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        log.err("unable to open: {s}", .{path});
        return err;
    };
    defer f.close();
    const target = try std.zig.system.abiAndDynamicLinkerFromFile(f, builtin.target.cpu, builtin.target.os, &.{}, .{});
    return try allocator.dupe(u8, target.dynamic_linker.get().?);
}

fn resolveArgs(allocator: std.mem.Allocator, appdir: []const u8, has_dl: *bool) ![]const []const u8 {
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
    const appdir = try std.fs.selfExeDirPathAlloc(allocator);
    defer allocator.free(appdir);

    var has_dl: bool = false;
    const args = try resolveArgs(allocator, appdir, &has_dl);
    defer {
        for (args) |arg| allocator.free(arg);
        allocator.free(args);
    }

    const exe = if (has_dl) args[1] else args[0];

    {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        runtime.setup(arena.allocator(), exe) catch |err| {
            log.warn("{}: runtime is incomplete and the program may not function properly", .{err});
        };
        _ = arena.reset(.retain_capacity);
        appimage.setup(arena.allocator(), appdir) catch |err| {
            log.err(
                \\Failed to setup an namespace inside the AppImage, cannot continue.
                \\Please run the .AppImage with argument --appimage-mount or --apimage-extract
                \\and try to run the binaries manually from there.
                , .{});
            return err;
        };
    }

    log.info("executing: {s}", .{exe});
    return std.process.execv(allocator, args);
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
