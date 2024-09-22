const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const SignerVerifier = struct {
    secret: []const u8,

    pub const signature_length = HmacSha256.mac_length;
    pub const alg_str = "HS256";

    pub fn init(secret: []const u8) SignerVerifier {
        return .{ .secret = secret };
    }

    pub fn sign(self: SignerVerifier, bytes: []const u8, buf: []u8) !void {
        var signature: [signature_length]u8 = undefined;
        HmacSha256.create(&signature, bytes, self.secret);
        @memcpy(buf, &signature);
    }

    pub fn verify(self: SignerVerifier, bytes: []const u8, sig: []const u8) !bool {
        // Duplicating this here to avoid copying 2 times
        var signature: [signature_length]u8 = undefined;
        HmacSha256.create(&signature, bytes, self.secret);

        return std.mem.eql(u8, &signature, sig);
    }
};

const jwt = @import("../jwt.zig");

test SignerVerifier {
    const bytes = "test bytes";

    const signer_verifier = SignerVerifier.init("testsecret");
    var signature: [SignerVerifier.signature_length]u8 = undefined;
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
