const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ziwt = b.addModule("ziwt", .{
        .root_source_file = b.path("src/ziwt.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Examples
    const examples_build = b.step("examples", "Build all examples");

    const examples = [_][]const u8{
        "jws-encode-decode",
    };

    inline for (&examples) |example_name| {
        const example_exe = b.addExecutable(.{
            .name = example_name,
            .root_source_file = b.path(b.pathJoin(&.{ "examples", b.fmt("{s}.zig", .{example_name}) })),
            .target = target,
            .optimize = optimize,
        });

        example_exe.root_module.addImport("ziwt", ziwt);

        const example_install = b.addInstallArtifact(example_exe, .{});
        examples_build.dependOn(&example_install.step);
    }

    // Tests
    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
