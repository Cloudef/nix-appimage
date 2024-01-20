const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    inline for (&.{"loader", "AppRun"}) |name| {
        const exe = b.addExecutable(.{
            .name = name,
            .root_source_file = .{ .path = "src/loader.zig" },
            .target = target,
            .optimize = optimize,
            .link_libc = false,
            .linkage = .static,
            .single_threaded = true,
        });

        b.installArtifact(exe);

        const is_loader = std.mem.eql(u8, name, "loader");
        const opts = b.addOptions();
        opts.addOption(bool, "appimage", !is_loader);
        exe.root_module.addOptions("options", opts);

        if (is_loader) {
            const run_cmd = b.addRunArtifact(exe);
            run_cmd.step.dependOn(b.getInstallStep());
            if (b.args) |args| run_cmd.addArgs(args);
            const run_step = b.step("run", "Run the standalone loader");
            run_step.dependOn(&run_cmd.step);
        }
    }
}
