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
