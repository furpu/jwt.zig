const std = @import("std");

pub fn SignerVerifier(comptime H: type, comptime alg: []const u8) type {
    return struct {
        secret: []const u8,

        pub const signature_length = H.mac_length;
        pub const alg_str = alg;

        const Self = @This();

        pub fn init(secret: []const u8) Self {
            return .{ .secret = secret };
        }

        pub fn sign(self: Self, bytes: []const u8, buf: []u8) !void {
            var signature: [signature_length]u8 = undefined;
            H.create(&signature, bytes, self.secret);
            @memcpy(buf, &signature);
        }

        pub fn verify(self: Self, bytes: []const u8, sig: []const u8) !bool {
            // Duplicating this here to avoid copying 2 times
            var signature: [signature_length]u8 = undefined;
            H.create(&signature, bytes, self.secret);
            return std.mem.eql(u8, &signature, sig);
        }
    };
}

const jwt = @import("../jwt.zig");
pub fn testSignerVerifier(signer_verifier: anytype) !void {
    const bytes = "test bytes";

    var signature: [@TypeOf(signer_verifier).signature_length]u8 = undefined;
    try signer_verifier.sign(bytes, &signature);

    {
        const valid = try signer_verifier.verify(bytes, &signature);
        try std.testing.expect(valid);
    }

    // Make sure we are following the signer and verifier interfaces correctly
    const encoded = try jwt.encode(std.testing.allocator, struct {}{}, signer_verifier);
    defer std.testing.allocator.free(encoded);

    const decoded = try jwt.decode(struct {}, std.testing.allocator, encoded, signer_verifier);
    defer decoded.deinit();
}
