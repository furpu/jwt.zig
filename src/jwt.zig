const std = @import("std");
const base64 = std.base64;
const json = std.json;
const Allocator = std.mem.Allocator;

const part_separator: u8 = '.';

const Header = struct {
    alg: []const u8,
    typ: ?[]const u8 = "JWT",
    cty: ?[]const u8 = null,
};

pub const Signer = struct {
    ptr: *anyopaque,
    vtable: VTable,
    alg_str: []const u8,

    pub const VTable = struct {
        sign_fn: *const fn (self: *anyopaque, bytes: []const u8, writer: std.io.AnyWriter) anyerror!void,
    };

    pub fn sign(self: Signer, bytes: []const u8, writer: std.io.AnyWriter) anyerror!void {
        return self.vtable.sign_fn(self.ptr, bytes, writer);
    }
};

pub const Verifier = struct {
    ptr: *anyopaque,
    vtable: VTable,

    pub const VTable = struct {
        verify_fn: *const fn (self: *anyopaque, bytes: []const u8, signature: []const u8) anyerror!bool,
    };

    pub fn verify(self: Verifier, bytes: []const u8, signature: []const u8) anyerror!bool {
        return self.vtable.verify_fn(self.ptr, bytes, signature);
    }
};

pub const Encoder = struct {
    signer: ?Signer,

    const b64_encoder = base64.url_safe_no_pad.Encoder;
    const json_strigify_opts: json.StringifyOptions = .{ .emit_null_optional_fields = false };

    pub const unsecure = Encoder{ .signer = null };

    pub fn encode(self: Encoder, comptime T: type, allocator: Allocator, claim_set: T) ![]const u8 {
        var header: Header = undefined;
        if (self.signer) |signer| {
            header = .{ .alg = signer.alg_str };
        } else {
            header = .{ .alg = "none", .typ = null };
        }

        // Create a buffer to store the encoded JWT
        var encoded_buffer = std.ArrayList(u8).init(allocator);
        errdefer encoded_buffer.deinit();
        const encoded_buffer_writer = encoded_buffer.writer().any();

        // Create a buffer to use for stringifying data into JSON
        var buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
        defer buffer.deinit();

        // Stringify and encode header
        try json.stringify(header, json_strigify_opts, buffer.writer().any());
        try b64_encoder.encodeWriter(encoded_buffer_writer, buffer.items);
        try encoded_buffer_writer.writeByte(part_separator);

        // Stringify and encode claim set
        buffer.clearRetainingCapacity();
        try json.stringify(claim_set, json_strigify_opts, buffer.writer().any());
        try b64_encoder.encodeWriter(encoded_buffer_writer, buffer.items);

        // Add signature if signer is present
        if (self.signer) |signer| {
            buffer.clearRetainingCapacity();
            try signer.sign(encoded_buffer.items, buffer.writer().any());
            try encoded_buffer_writer.writeByte(part_separator);
            try b64_encoder.encodeWriter(encoded_buffer_writer, buffer.items);
        } else {
            try encoded_buffer_writer.writeByte(part_separator);
        }

        return try encoded_buffer.toOwnedSlice();
    }
};

pub const Decoder = struct {
    verifier: ?Verifier,

    const b64_decoder = base64.url_safe_no_pad.Decoder;

    pub const unsecure = Decoder{ .verifier = null };

    pub fn decode(self: Decoder, comptime T: type, allocator: Allocator, encoded: []const u8) !json.Parsed(T) {
        var part_iter = std.mem.splitScalar(u8, encoded, '.');
        var parts_len: usize = 0;

        var header: json.Parsed(Header) = undefined;
        if (part_iter.next()) |encoded_header| {
            parts_len += encoded_header.len + 1;
            header = try parseBase64Json(Header, allocator, encoded_header);
        } else {
            return error.MissingHeader;
        }
        defer header.deinit();

        var claim_set: json.Parsed(T) = undefined;
        if (part_iter.next()) |encoded_claim_set| {
            parts_len += encoded_claim_set.len;
            claim_set = try parseBase64Json(T, allocator, encoded_claim_set);
        } else {
            return error.MissingClaimSet;
        }
        errdefer claim_set.deinit();

        if (self.verifier) |verifier| {
            if (part_iter.next()) |encoded_signature| {
                const decode_len = try b64_decoder.calcSizeForSlice(encoded_signature);
                const decode_buf = try allocator.alloc(u8, decode_len);
                defer allocator.free(decode_buf);

                try b64_decoder.decode(decode_buf, encoded_signature);

                const valid = try verifier.verify(encoded[0..parts_len], decode_buf);
                if (!valid) return error.InvalidSignature;
            } else {
                return error.MissingSignature;
            }
        }

        return claim_set;
    }

    fn parseBase64Json(comptime T: type, allocator: Allocator, encoded: []const u8) !json.Parsed(T) {
        const decoded_len = try b64_decoder.calcSizeForSlice(encoded);
        const buf = try allocator.alloc(u8, decoded_len);
        defer allocator.free(buf);

        try b64_decoder.decode(buf, encoded);
        return json.parseFromSlice(T, allocator, buf, .{ .allocate = .alloc_always });
    }
};

// TODO: Move this to be executed inside each of the signer tests (maybe by providing the signer as an arg to the test fn?)
test "encode does not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testEncodeMemoryErrors, .{});
}

fn testEncodeMemoryErrors(allocator: Allocator) !void {
    const claim_set = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };
    const encoded = try Encoder.unsecure.encode(@TypeOf(claim_set), allocator, claim_set);
    defer std.testing.allocator.free(encoded);
}

test "encode with alg=none" {
    // Test example from https://datatracker.ietf.org/doc/html/rfc7519#section-6.1
    // NOTE: I re-encoded the JWT after removing the claim set whitespaces.
    const expected = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

    const claim_set = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };
    const encoded = try Encoder.unsecure.encode(@TypeOf(claim_set), std.testing.allocator, claim_set);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqualStrings(expected, encoded);
}

// TODO: Move this to be executed inside each of the verifier tests (maybe by providing the verifier as an arg to the test fn?)
test "decode does not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testDecodeMemoryErrors, .{});
}

fn testDecodeMemoryErrors(allocator: Allocator) !void {
    const encoded = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
    const ClaimSet = struct {
        iss: []const u8,
        exp: u64,
        @"http://example.com/is_root": bool,
    };
    const claim_set = try Decoder.unsecure.decode(ClaimSet, allocator, encoded);
    defer claim_set.deinit();
}

test "decode with alg=none" {
    // Test example from https://datatracker.ietf.org/doc/html/rfc7519#section-6.1
    const encoded = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

    const ClaimSet = struct {
        iss: []const u8,
        exp: u64,
        @"http://example.com/is_root": bool,
    };
    const expected = ClaimSet{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const claim_set = try Decoder.unsecure.decode(ClaimSet, std.testing.allocator, encoded);
    defer claim_set.deinit();

    try std.testing.expectEqualDeep(expected, claim_set.value);
}
