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

const Executor = struct {
    args: []const []const u8,
    appdir: ?[]const u8,
    dynamic: bool,

    const Resolver = enum {
        standalone,
        appimage,
    };

    pub fn resolve(allocator: std.mem.Allocator, comptime resolver: Resolver) !@This() {
        const appdir = switch (resolver) {
            .standalone => null,
            .appimage => try std.fs.selfExeDirPathAlloc(allocator),
        };

        var iter = try std.process.argsWithAllocator(allocator);
        defer iter.deinit();
        _ = iter.skip();

        const exe = blk: {
            switch (resolver) {
                .standalone => {
                    if (iter.next()) |exe| {
                        break :blk try std.fs.realpathAlloc(allocator, exe);
                    } else {
                        std.log.err("usage: loader exe [args]", .{});
                        std.os.exit(1);
                    }
                },
                .appimage => {
                    const base = try std.fmt.allocPrint(allocator, "{s}/entrypoint", .{appdir});
                    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                    const link = std.fs.readLinkAbsolute(base, &buf) catch break :blk base;
                    allocator.free(base);
                    break :blk try std.fmt.allocPrint(allocator, "{s}{s}", .{appdir, link});
                }
            }
        };

        var args: std.ArrayListUnmanaged([]const u8) = .{};
        defer args.deinit(allocator);

        var dynamic = false;
        if (try dynamicLinkerFromPath(allocator, exe)) |dl0| {
            defer allocator.free(dl0);
            if (try dynamicLinkerFromPath(allocator, "/usr/bin/env")) |dl| {
                log.info("dynamic linker: {s}", .{dl});
                try args.append(allocator, dl);
            } else {
                log.warn("unable to figure out the dynamic linker, falling back to: {s}", .{dl0});
            }
            dynamic = true;
        }

        try args.append(allocator, exe);
        while (iter.next()) |arg| try args.append(allocator, try allocator.dupe(u8, arg));

        return .{
            .args = try args.toOwnedSlice(allocator),
            .appdir = appdir,
            .dynamic = dynamic,
        };
    }

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.args) |arg| allocator.free(arg);
        allocator.free(self.args);
    }

    pub fn exePath(self: @This()) []const u8 {
        return if (self.dynamic) self.args[1] else self.args[0];
    }
};

fn run(allocator: std.mem.Allocator) !void {
    const resolver = if (comptime @import("options").appimage) .appimage else .standalone;
    var executor = try Executor.resolve(allocator, resolver);
    defer executor.deinit(allocator);

    {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        runtime.setup(arena.allocator(), executor.exePath()) catch |err| {
            log.warn("{}: runtime is incomplete and the program may not function properly", .{err});
        };

        if (resolver == .appimage) {
            _ = arena.reset(.retain_capacity);
            appimage.setup(arena.allocator(), executor.appdir.?) catch |err| {
                log.err(
                    \\Failed to setup an namespace inside the AppImage, cannot continue.
                    \\Please run the .AppImage with argument --appimage-mount or --apimage-extract
                    \\and try to run the binaries manually from there.
                    , .{});
                return err;
            };
        }
    }

    log.info("executing: {s}", .{executor.exePath()});
    return std.process.execv(allocator, executor.args);
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
