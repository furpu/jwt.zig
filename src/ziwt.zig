pub const algorithms = @import("algorithms.zig");

const std = @import("std");
const base64 = std.base64;
const json = std.json;
const mem = std.mem;

const signature = algorithms.signature;

const Allocator = mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

/// JWT header.
pub const Header = struct {
    alg: []const u8,
    typ: ?[]const u8 = null,
};

/// Decoded JWT header and payload.
pub fn Decoded(comptime PayloadT: type) type {
    return struct {
        arena: *ArenaAllocator,
        header: Header,
        payload: PayloadT,

        const Self = @This();

        pub fn deinit(self: Self) void {
            self.arena.deinit();
            self.arena.child_allocator.destroy(self.arena);
        }
    };
}

/// JWT encoder and decoder.
pub const Codec = struct {
    _enc: base64.Base64Encoder = base64.Base64Encoder.init(base64.url_safe_no_pad.alphabet_chars, base64.url_safe_no_pad.pad_char),
    _dec: base64.Base64Decoder = base64.Base64Decoder.init(base64.url_safe_no_pad.alphabet_chars, base64.url_safe_no_pad.pad_char),

    /// Signature algorithm used to sign and verify the encoded/decoded JWT signatures.
    sig_algorithm: ?signature.Algorithm = null,

    /// Returns a JWT containing the given payload.
    ///
    /// The signature part of the JWT is created using the Codec's configured algorithm
    /// and the given key.
    ///
    /// The caller owns the memory allocated for the JWT.
    pub fn encode(self: Codec, allocator: Allocator, payload: anytype) ![]const u8 {
        var header = Header{ .alg = "none" };
        if (self.sig_algorithm) |alg| {
            header.alg = alg.alg_str;
            header.typ = "JWT";
        }

        var token = std.ArrayList(u8).init(allocator);
        errdefer token.deinit();

        try self.appendEncodedJSON(allocator, header, &token);
        (try token.addOne()).* = '.';
        try self.appendEncodedJSON(allocator, payload, &token);

        try self.maybeAppendSignature(allocator, &token);

        return try token.toOwnedSlice();
    }

    /// Decodes and verifies a JWT and returns the payload part as a value of type T.
    ///
    /// The caller should free the memory of the returned value.
    pub fn decode(self: Codec, comptime PayloadT: type, allocator: Allocator, s: []const u8) !Decoded(PayloadT) {
        const token_pieces = try TokenPieces.fromString(s);

        const jwt_arena_alloc = try allocator.create(ArenaAllocator);
        jwt_arena_alloc.* = ArenaAllocator.init(allocator);
        const jwt_arena = jwt_arena_alloc.allocator();

        // Decode and parse header so we know which algorithm to use
        const header_json = try allocator.alloc(u8, try self._dec.calcSizeForSlice(token_pieces.header));
        defer allocator.free(header_json);

        try self._dec.decode(header_json, token_pieces.header);
        const header = try json.parseFromSliceLeaky(Header, jwt_arena, header_json, .{ .allocate = .alloc_always });

        // Check signature
        if (self.sig_algorithm) |alg| {
            if (!mem.eql(u8, alg.alg_str, header.alg)) {
                return error.WrongAlg;
            }
        } else if (!mem.eql(u8, "none", header.alg)) {
            return error.WrongAlg;
        }

        // Decode and parse the payload
        const payload_json = try allocator.alloc(u8, try self._dec.calcSizeForSlice(token_pieces.payload));
        defer allocator.free(payload_json);

        try self._dec.decode(payload_json, token_pieces.payload);
        const payload = try json.parseFromSliceLeaky(PayloadT, jwt_arena, payload_json, .{ .allocate = .alloc_always });

        return Decoded(PayloadT){
            .arena = jwt_arena_alloc,
            .header = header,
            .payload = payload,
        };
    }

    fn appendEncoded(self: Codec, bs: []const u8, arr: *std.ArrayList(u8)) !void {
        const slice = try arr.addManyAsSlice(self._enc.calcSize(bs.len));
        _ = self._enc.encode(slice, bs);
    }

    fn appendEncodedJSON(self: Codec, allocator: Allocator, val: anytype, arr: *std.ArrayList(u8)) !void {
        const val_json = try json.stringifyAlloc(allocator, val, .{ .emit_null_optional_fields = false });
        defer allocator.free(val_json);

        try self.appendEncoded(val_json, arr);
    }

    fn maybeAppendSignature(self: Codec, allocator: Allocator, arr: *std.ArrayList(u8)) !void {
        var sig: ?[]u8 = null;
        defer {
            if (sig) |sig_ptr| {
                allocator.free(sig_ptr);
            }
        }

        if (self.sig_algorithm) |alg| {
            sig = try alg.sign(allocator, arr.items);
        }

        (try arr.addOne()).* = '.';

        if (sig) |sig_bytes| {
            try self.appendEncoded(sig_bytes, arr);
        }
    }
};

/// Used internally to parse the JWT string parts.
const TokenPieces = struct {
    header: []const u8,
    payload: []const u8,
    signature: []const u8,

    fn fromString(s: []const u8) !TokenPieces {
        var self = TokenPieces{
            .header = undefined,
            .payload = undefined,
            .signature = undefined,
        };

        var parts_iter = std.mem.splitScalar(u8, s, '.');

        if (parts_iter.next()) |part| {
            self.header = part;
        } else {
            return error.InvalidFormat;
        }

        if (parts_iter.next()) |part| {
            self.payload = part;
        } else {
            return error.InvalidFormat;
        }

        if (parts_iter.next()) |part| {
            self.signature = part;
        } else {
            return error.InvalidFormat;
        }

        return self;
    }
};

const test_secret = "testsecret";
var test_hs256 = signature.Hs256{ .secret = test_secret };

test "JWT encode with alg=hs256" {
    const codec = Codec{ .sig_algorithm = test_hs256.algorithm() };

    const enc_str = try codec.encode(std.testing.allocator, .{ .test_str = "str1" });
    defer std.testing.allocator.free(enc_str);

    const expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0X3N0ciI6InN0cjEifQ.6_xNniyaF5scigAozuaxxdWtdlnI1CAP8OHDTcBi9i8";

    try std.testing.expectEqualStrings(expected, enc_str);
}

test "JWT encode with alg=none" {
    const codec = Codec{};
    const enc_str = try codec.encode(std.testing.allocator, .{ .test_str = "str1" });
    defer std.testing.allocator.free(enc_str);

    const expected = "eyJhbGciOiJub25lIn0.eyJ0ZXN0X3N0ciI6InN0cjEifQ.";

    try std.testing.expectEqualStrings(expected, enc_str);
}

test "JWT decode alg=hs256" {
    const codec = Codec{ .sig_algorithm = test_hs256.algorithm() };
    const enc_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0X2ZpZWxkIjo1fQ.kwVT7OeKoswn-5rjGKuKr7NUGQx5rAuRA3THFtwqp3Y";

    const dec_jwt = try codec.decode(struct { test_field: i32 }, std.testing.allocator, enc_str);
    defer dec_jwt.deinit();

    try std.testing.expectEqual(5, dec_jwt.payload.test_field);
}

test "JWT decode alg=none" {
    const codec = Codec{};
    const enc_str = "eyJhbGciOiJub25lIn0.eyJ0ZXN0X2ZpZWxkIjo1fQ.";

    const dec_jwt = try codec.decode(struct { test_field: i32 }, std.testing.allocator, enc_str);
    defer dec_jwt.deinit();

    try std.testing.expectEqual(5, dec_jwt.payload.test_field);
}
