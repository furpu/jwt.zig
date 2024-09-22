const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const jwt = b.addModule("jwt", .{
        .root_source_file = b.path("src/jwt.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cricket = b.dependency("cricket", .{
        .target = target,
        .optimize = optimize,
    });
    jwt.addImport("cricket", cricket.module("cricket"));

    // Examples
    const example_step = b.step("examples", "Build examples");
    const example_filenames = [_][]const u8{
        "encode.zig",
        "decode.zig",
    };

    for (example_filenames) |filename| {
        const example_name = blk: {
            var iter = std.mem.splitScalar(u8, filename, '.');
            break :blk iter.next().?;
        };

        const example_exe = b.addExecutable(.{
            .name = example_name,
            .root_source_file = b.path(b.pathJoin(&.{ "examples", filename })),
            .target = target,
            .optimize = optimize,
        });
        example_exe.root_module.addImport("jwt", jwt);

        const install_example_exe = b.addInstallArtifact(example_exe, .{});

        example_step.dependOn(&install_example_exe.step);
    }

    // Tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/jwt.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addImport("cricket", cricket.module("cricket"));

    const run_exe_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
