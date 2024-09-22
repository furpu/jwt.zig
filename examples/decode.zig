const std = @import("std");
const jwt = @import("jwt");

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("missing EC private or public key file path\n", .{});
        return 1;
    }
    if (args.len < 3) {
        std.debug.print("missing JWT\n", .{});
        return 1;
    }

    const verifier = blk: {
        const f = try std.fs.cwd().openFileZ(args[1], .{});
        defer f.close();

        const pem = try f.readToEndAlloc(allocator, 10 * 1024 * 1024);
        defer allocator.free(pem);

        const verifier = try jwt.algorithms.es256.Verifier.fromPem(allocator, pem);
        break :blk verifier;
    };

    const decoded = try jwt.decode(std.json.Value, allocator, args[2], verifier);
    defer decoded.deinit();

    const claim_set_str = try std.json.stringifyAlloc(allocator, decoded.value, .{ .whitespace = .indent_2 });
    defer allocator.free(claim_set_str);

    std.debug.print("{s}\n", .{claim_set_str});

    return 0;
}
