const std = @import("std");
const jwt = @import("jwt");

const ClaimSet = struct {
    iss: []const u8,
};

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("missing EC private key file path\n", .{});
        return 1;
    }

    const signer = blk: {
        const f = try std.fs.cwd().openFileZ(args[1], .{});
        defer f.close();

        const pem = try f.readToEndAlloc(allocator, 10 * 1024 * 1024);
        defer allocator.free(pem);

        const signer = try jwt.algorithms.es256.SignerVerifier.fromPem(allocator, pem);
        break :blk signer;
    };

    const encoded = try jwt.encode(allocator, ClaimSet{ .iss = "issuer" }, signer);
    defer allocator.free(encoded);

    std.debug.print("{s}\n", .{encoded});
    return 0;
}
