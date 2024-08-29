const std = @import("std");
const base64 = std.base64;
const json = std.json;

const Allocator = std.mem.Allocator;

const Header = struct {
    alg: []const u8,
    typ: ?[]const u8,
};

pub const Algorithm = enum(u8) {
    none = 0,
    hs256,

    const strs = [_][]const u8{
        "none",
        "HS256",
    };

    inline fn header(self: Algorithm) Header {
        var typ: ?[]const u8 = null;
        if (self != .none) {
            typ = "JWT";
        }

        return .{
            .alg = strs[@intFromEnum(self)],
            .typ = typ,
        };
    }
};

pub const Codec = struct {
    _enc: base64.Base64Encoder = base64.Base64Encoder.init(base64.url_safe_no_pad.alphabet_chars, base64.url_safe_no_pad.pad_char),
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

    pub fn decode(allocator: Allocator, comptime T: type) !T {
        _ = allocator;

        return undefined;
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

test "JWT decode" {}
