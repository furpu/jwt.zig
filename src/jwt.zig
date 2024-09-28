//! JWT encoding and decoding.

const std = @import("std");
const base64 = std.base64;
const json = std.json;
const Allocator = std.mem.Allocator;

pub const algorithms = @import("algorithms.zig");

const b64_encoder = base64.url_safe_no_pad.Encoder;
const b64_decoder = base64.url_safe_no_pad.Decoder;
const json_strigify_opts: json.StringifyOptions = .{ .emit_null_optional_fields = false };
const part_separator: u8 = '.';

const Header = struct {
    alg: []const u8,
    typ: ?[]const u8 = "JWT",
    cty: ?[]const u8 = null,
};

/// Encodes a claim set into a JWT string using the given signer to generate the signature.
///
/// If signer is `null`, this encodes a unsecure JWT (i.e. no signature).
pub fn encode(allocator: Allocator, claim_set: anytype, signer: anytype) ![]const u8 {
    const SignerT = @TypeOf(signer);

    const is_null_signer = switch (@typeInfo(SignerT)) {
        .null => true,
        else => false,
    };

    var signature_length: usize = 0;
    var header: Header = .{ .alg = "none", .typ = null };
    if (!is_null_signer) {
        signature_length = SignerT.signature_length;
        header = .{ .alg = SignerT.alg_str };
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
    if (is_null_signer) {
        try encoded_buffer_writer.writeByte(part_separator);
    } else {
        buffer.clearRetainingCapacity();
        try buffer.appendNTimes(0, signature_length);
        try signer.sign(encoded_buffer.items, buffer.items);
        try encoded_buffer_writer.writeByte(part_separator);
        try b64_encoder.encodeWriter(encoded_buffer_writer, buffer.items);
    }

    return try encoded_buffer.toOwnedSlice();
}

/// Decodes a JWT string and parse its claim set into a value of type `T`.
///
/// The given verifier is used to verify the JWT signature. If verifier is `null`, no signature verification is done.
pub fn decode(comptime T: type, allocator: Allocator, encoded: []const u8, verifier: anytype) !json.Parsed(T) {
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

    const is_null_verifier = switch (@typeInfo(@TypeOf(verifier))) {
        .null => true,
        else => false,
    };

    if (!is_null_verifier) {
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

test {
    std.testing.refAllDeclsRecursive(@This());
}

test "encode with alg=none does not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testEncodeMemoryErrors, .{});
}

fn testEncodeMemoryErrors(allocator: Allocator) !void {
    const claim_set = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };
    const encoded = try encode(allocator, claim_set, null);
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
    const encoded = try encode(std.testing.allocator, claim_set, null);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqualStrings(expected, encoded);
}

test "decode with alg=none does not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testDecodeMemoryErrors, .{});
}

fn testDecodeMemoryErrors(allocator: Allocator) !void {
    const encoded = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
    const ClaimSet = struct {
        iss: []const u8,
        exp: u64,
        @"http://example.com/is_root": bool,
    };
    const claim_set = try decode(ClaimSet, allocator, encoded, null);
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

    const claim_set = try decode(ClaimSet, std.testing.allocator, encoded, null);
    defer claim_set.deinit();

    try std.testing.expectEqualDeep(expected, claim_set.value);
}
