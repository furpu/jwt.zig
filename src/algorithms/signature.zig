const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

/// Interface for all signature algorithms supported by the library.
pub const Algorithm = struct {
    pub const VTable = struct {
        sign: *const fn (self: *anyopaque, allocator: mem.Allocator, bytes: []const u8) anyerror![]u8,
        verify: *const fn (self: *anyopaque, sig_bytes: []const u8, bytes: []const u8) anyerror!bool,
    };

    _ptr: *anyopaque,
    _vtable: *const VTable,

    alg_str: []const u8,

    /// Returns the signature for the given bytes.
    ///
    /// Caller owns the returned memory and should free it.
    pub inline fn sign(self: Algorithm, allocator: mem.Allocator, bytes: []const u8) anyerror![]u8 {
        return self._vtable.sign(self._ptr, allocator, bytes);
    }

    /// Returns whether sig_bytes corresponds to the signature for the given bytes.
    pub inline fn verify(self: Algorithm, sig_bytes: []const u8, bytes: []const u8) anyerror!bool {
        return self._vtable.verify(self._ptr, sig_bytes, bytes);
    }
};

/// HS256 signer and verifier.
pub const Hs256 = struct {
    secret: []const u8,

    const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

    pub const sig_length = HmacSha256.mac_length;
    pub const alg_str = "HS256";

    const vtable = Algorithm.VTable{
        .sign = algorithmSign,
        .verify = algorithmVerify,
    };

    pub fn sign(self: Hs256, allocator: mem.Allocator, bytes: []const u8) ![]u8 {
        var sig_bytes: [sig_length]u8 = undefined;
        HmacSha256.create(&sig_bytes, bytes, self.secret);

        const ret = try allocator.alloc(u8, sig_length);
        @memcpy(ret, sig_bytes[0..]);

        return ret;
    }

    pub fn verify(self: Hs256, sig_bytes: []const u8, bytes: []const u8) anyerror!bool {
        var computed_sig_bytes: [sig_length]u8 = undefined;
        HmacSha256.create(&computed_sig_bytes, bytes, self.secret);

        return mem.eql(u8, &computed_sig_bytes, sig_bytes);
    }

    pub fn algorithm(self: *Hs256) Algorithm {
        return .{
            ._ptr = self,
            ._vtable = &vtable,
            .alg_str = alg_str,
        };
    }

    fn algorithmSign(self: *anyopaque, allocator: mem.Allocator, bytes: []const u8) anyerror![]u8 {
        const this: *const Hs256 = @alignCast(@ptrCast(self));
        return this.sign(allocator, bytes);
    }

    fn algorithmVerify(self: *anyopaque, sig_bytes: []const u8, bytes: []const u8) anyerror!bool {
        const this: *const Hs256 = @alignCast(@ptrCast(self));
        return this.verify(sig_bytes, bytes);
    }
};

/// ES256 signer and verifier.
pub const Es256 = struct {
    keypair: EcdsaP256Sha256.KeyPair,

    const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;

    pub const seed_length = EcdsaP256Sha256.KeyPair.seed_length;
    pub const sig_length = EcdsaP256Sha256.Signature.encoded_length;
    pub const alg_str = "ES256";

    const vtable = Algorithm.VTable{
        .sign = algorithmSign,
        .verify = algorithmVerify,
    };

    pub inline fn create(seed: [seed_length]u8) !Es256 {
        const keypair = try EcdsaP256Sha256.KeyPair.create(seed);
        return Es256{ .keypair = keypair };
    }

    pub inline fn generate() !Es256 {
        const keypair = try EcdsaP256Sha256.KeyPair.generate();
        return Es256{ .keypair = keypair };
    }

    pub fn sign(self: Es256, allocator: mem.Allocator, bytes: []const u8) ![]u8 {
        // TODO: Should noise be used in this case?
        const sig = try self.keypair.sign(bytes, null);

        const ret = try allocator.alloc(u8, sig_length);
        @memcpy(ret, &sig.toBytes());

        return ret;
    }

    pub fn verify(self: Es256, sig_bytes: []const u8, bytes: []const u8) !bool {
        if (sig_bytes.len != sig_length) {
            return error.InvalidSignatureLength;
        }

        var sig_bytes_arr: [sig_length]u8 = undefined;
        @memcpy(&sig_bytes_arr, sig_bytes);

        const sig = EcdsaP256Sha256.Signature.fromBytes(sig_bytes_arr);

        sig.verify(bytes, self.keypair.public_key) catch |err| {
            switch (err) {
                error.SignatureVerificationFailed => return false,
                else => return err,
            }
        };

        return true;
    }

    pub fn algorithm(self: *Es256) Algorithm {
        return Algorithm{
            ._ptr = self,
            ._vtable = &vtable,
            .alg_str = alg_str,
        };
    }

    fn algorithmSign(self: *anyopaque, allocator: mem.Allocator, bytes: []const u8) anyerror![]u8 {
        const this: *Es256 = @alignCast(@ptrCast(self));
        return this.sign(allocator, bytes);
    }

    fn algorithmVerify(self: *anyopaque, sig_bytes: []const u8, bytes: []const u8) anyerror!bool {
        const this: *Es256 = @alignCast(@ptrCast(self));
        return this.verify(sig_bytes, bytes);
    }
};
