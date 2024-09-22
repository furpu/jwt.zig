const std = @import("std");
const Allocator = std.mem.Allocator;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const jwt = @import("../jwt.zig");
const cricket = @import("cricket");

pub const Signer = struct {
    keypair: EcdsaP256Sha256.KeyPair,
    verifier: Verifier,

    pub const alg_str = "ES256";
    pub const signature_length = EcdsaP256Sha256.Signature.encoded_length;

    pub fn init(keypair: EcdsaP256Sha256.KeyPair) Signer {
        return .{
            .keypair = keypair,
            .verifier = Verifier.init(keypair.public_key),
        };
    }

    pub fn generate() !Signer {
        const keypair = try EcdsaP256Sha256.KeyPair.generate();
        return init(keypair);
    }

    pub fn fromPem(allocator: Allocator, pem: []const u8) !Signer {
        var decoded = try cricket.decode.fromPem(allocator, pem);
        defer decoded.deinit();

        if (decoded.value.kind != .ec_private_key) return error.NotPrivateKey;

        var key_bytes: [EcdsaP256Sha256.SecretKey.encoded_length]u8 = undefined;
        @memcpy(&key_bytes, decoded.value.bytes);

        const secret_key = try EcdsaP256Sha256.SecretKey.fromBytes(key_bytes);
        const keypair = try EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key);

        return init(keypair);
    }

    pub fn sign(self: Signer, bytes: []const u8, buf: []u8) !void {
        const sig = try self.keypair.sign(bytes, null);
        const sig_bytes = sig.toBytes();
        @memcpy(buf, &sig_bytes);
    }
};

pub const Verifier = struct {
    public_key: EcdsaP256Sha256.PublicKey,

    pub fn init(public_key: EcdsaP256Sha256.PublicKey) Verifier {
        return .{ .public_key = public_key };
    }

    pub fn fromPem(allocator: Allocator, pem: []const u8) !Verifier {
        var decoded = try cricket.decode.fromPem(allocator, pem);
        defer decoded.deinit();

        if (decoded.value.kind != .ec_public_key) return error.NotPublicKey;
        const public_key = try EcdsaP256Sha256.PublicKey.fromSec1(decoded.value.bytes);

        return .{ .public_key = public_key };
    }

    pub fn verify(self: Verifier, bytes: []const u8, sig: []const u8) !bool {
        if (sig.len != EcdsaP256Sha256.Signature.encoded_length) return error.IncorrectSignatureLength;

        var buf: [EcdsaP256Sha256.Signature.encoded_length]u8 = undefined;
        @memcpy(&buf, sig);

        const signature = EcdsaP256Sha256.Signature.fromBytes(buf);
        signature.verify(bytes, self.public_key) catch |err| {
            switch (err) {
                error.SignatureVerificationFailed => return false,
                else => |other_err| return other_err,
            }
        };

        return true;
    }
};

test Signer {
    const sk_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
        \\OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
        \\1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
        \\-----END PRIVATE KEY-----
    ;
    const pk_pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
        \\q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
        \\-----END PUBLIC KEY-----
    ;

    var signer = try Signer.fromPem(std.testing.allocator, sk_pem);

    const bytes = "test bytes";
    var signature: [EcdsaP256Sha256.Signature.encoded_length]u8 = undefined;
    try signer.sign(bytes, &signature);

    {
        const valid = try signer.verifier.verify(bytes, &signature);
        try std.testing.expect(valid);
    }

    {
        var verifier = try Verifier.fromPem(std.testing.allocator, pk_pem);

        const valid = try verifier.verify(bytes, &signature);
        try std.testing.expect(valid);
    }

    const ClaimSet = struct {
        iss: []const u8,
    };
    const encoded = try jwt.encode(std.testing.allocator, ClaimSet{ .iss = "test" }, signer);
    defer std.testing.allocator.free(encoded);
    std.debug.print("{s}\n", .{encoded});

    const decoded = try jwt.decode(ClaimSet, std.testing.allocator, encoded, signer.verifier);
    defer decoded.deinit();
    std.debug.print("{}\n", .{decoded.value});
}
