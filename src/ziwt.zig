const std = @import("std");
const base64 = std.base64;
const json = std.json;
const mem = std.mem;

const Allocator = mem.Allocator;

const Header = struct {
    alg: []const u8,
    typ: ?[]const u8 = null,
};

pub const Algorithm = enum(u8) {
    none = 0,
    hs256,

    const strs = [_][]const u8{
        "none",
        "HS256",
    };

    fn parseFromString(s: []const u8) !Algorithm {
        // TODO: reimplement this in a smarter way.
        // An actual simple parser should be faster.
        if (mem.eql(u8, "none", s)) {
            return .none;
        } else if (mem.eql(u8, "HS256", s)) {
            return .hs256;
        }

        return error.InvalidOrUnknownAlgorithm;
    }

    fn header(self: Algorithm) Header {
        var h = Header{ .alg = strs[@intFromEnum(self)] };

        if (self != .none) {
            h.typ = "JWT";
        }

        return h;
    }
};

pub const Codec = struct {
    _enc: base64.Base64Encoder = base64.Base64Encoder.init(base64.url_safe_no_pad.alphabet_chars, base64.url_safe_no_pad.pad_char),
    _dec: base64.Base64Decoder = base64.Base64Decoder.init(base64.url_safe_no_pad.alphabet_chars, base64.url_safe_no_pad.pad_char),
    key: []const u8,

    pub fn encode(self: Codec, allocator: Allocator, alg: Algorithm, payload: anytype) ![]const u8 {
        const header = alg.header();

        var token = std.ArrayList(u8).init(allocator);
        errdefer token.deinit();

        try self.appendEncodedJSON(allocator, header, &token);
        (try token.addOne()).* = '.';
        try self.appendEncodedJSON(allocator, payload, &token);

        try self.maybeAppendSignature(alg, &token);

        return try token.toOwnedSlice();
    }

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

    pub fn decode(self: Codec, comptime T: type, allocator: Allocator, s: []const u8) !json.Parsed(T) {
        const token_pieces = try TokenPieces.fromString(s);

        // Decode and parse header so we know which algorithm to use
        const header_json = try allocator.alloc(u8, try self._dec.calcSizeForSlice(token_pieces.header));
        defer allocator.free(header_json);

        try self._dec.decode(header_json, token_pieces.header);
        const parsed_header = try json.parseFromSlice(Header, allocator, header_json, .{});
        defer parsed_header.deinit();

        // Decode and check signature
        const alg = try Algorithm.parseFromString(parsed_header.value.alg);
        switch (alg) {
            .none => {
                if (token_pieces.signature.len > 0) {
                    return error.InvalidSignature;
                }
            },
            .hs256 => {
                if (token_pieces.signature.len == 0) {
                    return error.InvalidSignature;
                }

                const sig_bytes = try allocator.alloc(u8, try self._dec.calcSizeForSlice(token_pieces.signature));
                defer allocator.free(sig_bytes);

                try self._dec.decode(sig_bytes, token_pieces.signature);

                const content_bytes = s[0..(token_pieces.header.len + token_pieces.payload.len + 1)];

                var computed_sig: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
                std.crypto.auth.hmac.sha2.HmacSha256.create(&computed_sig, content_bytes, self.key);

                if (!mem.eql(u8, &computed_sig, sig_bytes)) {
                    return error.InvalidSignature;
                }
            },
        }

        // Decode and parse the payload
        const payload_json = try allocator.alloc(u8, try self._dec.calcSizeForSlice(token_pieces.payload));
        defer allocator.free(payload_json);

        try self._dec.decode(payload_json, token_pieces.payload);
        const payload = try json.parseFromSlice(T, allocator, payload_json, .{ .allocate = .alloc_always });

        return payload;
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

    fn maybeAppendSignature(self: Codec, alg: Algorithm, arr: *std.ArrayList(u8)) !void {
        var sig: ?[]const u8 = null;
        switch (alg) {
            .hs256 => {
                var sig_out: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
                std.crypto.auth.hmac.sha2.HmacSha256.create(&sig_out, arr.items, self.key);

                sig = &sig_out;
            },
            .none => {},
        }

        (try arr.addOne()).* = '.';

        if (sig) |sig_bytes| {
            try self.appendEncoded(sig_bytes, arr);
        }
    }
};

const test_secret = "testsecret";

test "JWT encode with alg=hs256" {
    const codec = Codec{ .key = test_secret };
    const enc_str = try codec.encode(std.testing.allocator, .hs256, .{ .test_str = "str1" });
    defer std.testing.allocator.free(enc_str);

    const expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0X3N0ciI6InN0cjEifQ.6_xNniyaF5scigAozuaxxdWtdlnI1CAP8OHDTcBi9i8";

    try std.testing.expectEqualStrings(expected, enc_str);
}

test "JWT encode with alg=none" {
    const codec = Codec{ .key = test_secret };
    const enc_str = try codec.encode(std.testing.allocator, .none, .{ .test_str = "str1" });
    defer std.testing.allocator.free(enc_str);

    const expected = "eyJhbGciOiJub25lIn0.eyJ0ZXN0X3N0ciI6InN0cjEifQ.";

    try std.testing.expectEqualStrings(expected, enc_str);
}

test "JWT decode alg=hs256" {
    const codec = Codec{ .key = test_secret };
    const enc_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0X2ZpZWxkIjo1fQ.kwVT7OeKoswn-5rjGKuKr7NUGQx5rAuRA3THFtwqp3Y";

    const payload = try codec.decode(struct { test_field: i32 }, std.testing.allocator, enc_str);
    defer payload.deinit();

    try std.testing.expectEqual(5, payload.value.test_field);
}

test "JWT decode alg=none" {
    const codec = Codec{ .key = test_secret };
    const enc_str = "eyJhbGciOiJub25lIn0.eyJ0ZXN0X2ZpZWxkIjo1fQ.";

    const payload = try codec.decode(struct { test_field: i32 }, std.testing.allocator, enc_str);
    defer payload.deinit();

    try std.testing.expectEqual(5, payload.value.test_field);
}
