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

    var readme_example_step: *std.Build.Step = undefined;

    for (&examples, 0..) |example_name, i| {
        const example_exe = b.addExecutable(.{
            .name = example_name,
            .root_source_file = b.path(b.pathJoin(&.{ "examples", b.fmt("{s}.zig", .{example_name}) })),
            .target = target,
            .optimize = optimize,
        });

        example_exe.root_module.addImport("ziwt", ziwt);

        const example_install = b.addInstallArtifact(example_exe, .{});
        examples_build.dependOn(&example_install.step);

        // Record this so we can use it as a depency for the readme step.
        if (i == 0) {
            readme_example_step = &example_exe.step;
        }
    }

    // Readme
    const readme_step = b.step("readme", "Updates README.md");
    const update_readme = readmeStep(b);
    update_readme.dependOn(readme_example_step);
    readme_step.dependOn(update_readme);

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

fn readmeStep(b: *std.Build) *std.Build.Step {
    const step = b.allocator.create(std.Build.Step) catch unreachable;

    step.* = std.Build.Step.init(.{
        .id = .custom,
        .name = "ReadmeStep",
        .owner = b,
        .makeFn = readmeStepMake,
    });

    return step;
}

fn readmeStepMake(_: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
    const template = @embedFile("README.template.md");
    const example_code = @embedFile("examples/jws-encode-decode.zig");

    const out_f = try std.fs.cwd().createFile("README.md", .{ .truncate = true });
    defer out_f.close();

    const out_w = out_f.writer();
    try out_w.print(template, .{example_code});

    std.debug.print("Generated README.md\n", .{});
}
