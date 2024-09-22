const std = @import("std");
const Allocator = std.mem.Allocator;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const cricket = @import("cricket");

pub const SignerVerifier = struct {
    keypair: EcdsaP256Sha256.KeyPair,
    verifier: Verifier,

    pub const alg_str = "ES256";
    pub const signature_length = EcdsaP256Sha256.Signature.encoded_length;

    pub fn init(keypair: EcdsaP256Sha256.KeyPair) SignerVerifier {
        return .{
            .keypair = keypair,
            .verifier = Verifier.init(keypair.public_key),
        };
    }

    pub fn generate() !SignerVerifier {
        const keypair = try EcdsaP256Sha256.KeyPair.generate();
        return init(keypair);
    }

    pub fn fromPem(allocator: Allocator, pem: []const u8) !SignerVerifier {
        var decoded = try cricket.decode.fromPem(allocator, pem);
        defer decoded.deinit();

        if (decoded.value.kind != .ec_private_key) return error.NotPrivateKey;
        const keypair = try keypairFromPrivateKeyBytes(decoded.value.bytes);

        return init(keypair);
    }

    pub fn sign(self: SignerVerifier, bytes: []const u8, buf: []u8) !void {
        const sig = try self.keypair.sign(bytes, null);
        const sig_bytes = sig.toBytes();
        @memcpy(buf, &sig_bytes);
    }

    pub fn verify(self: SignerVerifier, bytes: []const u8, sig: []const u8) !bool {
        return self.verifier.verify(bytes, sig);
    }
};

pub const Verifier = struct {
    public_key: EcdsaP256Sha256.PublicKey,

    pub const signature_length = EcdsaP256Sha256.Signature.encoded_length;

    pub fn init(public_key: EcdsaP256Sha256.PublicKey) Verifier {
        return .{ .public_key = public_key };
    }

    pub fn fromSecretKeyBytes(sk: []const u8) !Verifier {
        const keypair = try keypairFromPrivateKeyBytes(sk);
        return init(keypair.public_key);
    }

    pub fn fromPem(allocator: Allocator, pem: []const u8) !Verifier {
        var decoded = try cricket.decode.fromPem(allocator, pem);
        defer decoded.deinit();

        switch (decoded.value.kind) {
            .ec_public_key => {
                const public_key = try EcdsaP256Sha256.PublicKey.fromSec1(decoded.value.bytes);
                return .{ .public_key = public_key };
            },
            .ec_private_key => {
                return fromSecretKeyBytes(decoded.value.bytes);
            },
        }
    }

    pub fn verify(self: Verifier, bytes: []const u8, sig: []const u8) !bool {
        if (sig.len != signature_length) return error.IncorrectSignatureLength;

        var buf: [signature_length]u8 = undefined;
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

fn keypairFromPrivateKeyBytes(sk: []const u8) !EcdsaP256Sha256.KeyPair {
    var key_bytes: [EcdsaP256Sha256.SecretKey.encoded_length]u8 = undefined;
    @memcpy(&key_bytes, sk);

    const secret_key = try EcdsaP256Sha256.SecretKey.fromBytes(key_bytes);
    const keypair = try EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key);

    return keypair;
}

const jwt = @import("../jwt.zig");

test SignerVerifier {
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
    const bytes = "test bytes";

    const signer_verifier = try SignerVerifier.fromPem(std.testing.allocator, sk_pem);
    var signature: [SignerVerifier.signature_length]u8 = undefined;
    try signer_verifier.sign(bytes, &signature);

    {
        const valid = try signer_verifier.verify(bytes, &signature);
        try std.testing.expect(valid);
    }

    {
        const verifier = try Verifier.fromPem(std.testing.allocator, pk_pem);
        const valid = try verifier.verify(bytes, &signature);
        try std.testing.expect(valid);
    }

    // Make sure we are following the signer and verifier interfaces correctly
    const encoded = try jwt.encode(std.testing.allocator, struct {}{}, signer_verifier);
    defer std.testing.allocator.free(encoded);

    const decoded = try jwt.decode(struct {}, std.testing.allocator, encoded, signer_verifier);
    defer decoded.deinit();
}
