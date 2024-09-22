const std = @import("std");
const Allocator = std.mem.Allocator;

const cricket = @import("cricket");

pub fn SignerVerifier(comptime Ecdsa: type, comptime alg: []const u8) type {
    return struct {
        keypair: Ecdsa.KeyPair,
        verifier: Verifier(Ecdsa),

        pub const alg_str = alg;
        pub const signature_length = Ecdsa.Signature.encoded_length;

        const Self = @This();

        pub fn init(keypair: Ecdsa.KeyPair) Self {
            return .{
                .keypair = keypair,
                .verifier = Verifier(Ecdsa).init(keypair.public_key),
            };
        }

        pub fn generate() !Self {
            const keypair = try Ecdsa.KeyPair.generate();
            return init(keypair);
        }

        pub fn fromPem(allocator: Allocator, pem: []const u8) !Self {
            var decoded = try cricket.decode.fromPem(allocator, pem);
            defer decoded.deinit();

            if (decoded.value.kind != .ec_private_key) return error.NotPrivateKey;
            const keypair = try keypairFromPrivateKeyBytes(Ecdsa, decoded.value.bytes);

            return init(keypair);
        }

        pub fn sign(self: Self, bytes: []const u8, buf: []u8) !void {
            const sig = try self.keypair.sign(bytes, null);
            const sig_bytes = sig.toBytes();
            @memcpy(buf, &sig_bytes);
        }

        pub fn verify(self: Self, bytes: []const u8, sig: []const u8) !bool {
            return self.verifier.verify(bytes, sig);
        }
    };
}

pub fn Verifier(comptime Ecdsa: type) type {
    return struct {
        public_key: Ecdsa.PublicKey,

        pub const signature_length = Ecdsa.Signature.encoded_length;

        const Self = @This();

        pub fn init(public_key: Ecdsa.PublicKey) Self {
            return .{ .public_key = public_key };
        }

        pub fn fromSecretKeyBytes(sk: []const u8) !Self {
            const keypair = try keypairFromPrivateKeyBytes(Ecdsa, sk);
            return init(keypair.public_key);
        }

        pub fn fromPem(allocator: Allocator, pem: []const u8) !Self {
            var decoded = try cricket.decode.fromPem(allocator, pem);
            defer decoded.deinit();

            switch (decoded.value.kind) {
                .ec_public_key => {
                    const public_key = try Ecdsa.PublicKey.fromSec1(decoded.value.bytes);
                    return .{ .public_key = public_key };
                },
                .ec_private_key => {
                    return fromSecretKeyBytes(decoded.value.bytes);
                },
            }
        }

        pub fn verify(self: Self, bytes: []const u8, sig: []const u8) !bool {
            if (sig.len != signature_length) return error.IncorrectSignatureLength;

            var buf: [signature_length]u8 = undefined;
            @memcpy(&buf, sig);

            const signature = Ecdsa.Signature.fromBytes(buf);
            signature.verify(bytes, self.public_key) catch |err| {
                switch (err) {
                    error.SignatureVerificationFailed => return false,
                    else => |other_err| return other_err,
                }
            };

            return true;
        }
    };
}

fn keypairFromPrivateKeyBytes(comptime Ecdsa: type, sk: []const u8) !Ecdsa.KeyPair {
    var key_bytes: [Ecdsa.SecretKey.encoded_length]u8 = undefined;
    @memcpy(&key_bytes, sk);

    const secret_key = try Ecdsa.SecretKey.fromBytes(key_bytes);
    const keypair = try Ecdsa.KeyPair.fromSecretKey(secret_key);

    return keypair;
}

const jwt = @import("../jwt.zig");
pub fn testSignerVerifier(signer_verifier: anytype, verifier: anytype) !void {
    const bytes = "test bytes";

    var signature: [@TypeOf(signer_verifier).signature_length]u8 = undefined;
    try signer_verifier.sign(bytes, &signature);

    {
        const valid = try signer_verifier.verify(bytes, &signature);
        try std.testing.expect(valid);
    }

    {
        const valid = try verifier.verify(bytes, &signature);
        try std.testing.expect(valid);
    }

    // Make sure we are following the signer and verifier interfaces correctly
    const encoded = try jwt.encode(std.testing.allocator, struct {}{}, signer_verifier);
    defer std.testing.allocator.free(encoded);

    const decoded = try jwt.decode(struct {}, std.testing.allocator, encoded, signer_verifier);
    defer decoded.deinit();
}
