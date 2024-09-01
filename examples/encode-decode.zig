const std = @import("std");
const jwt = @import("jwt");

const ExamplePayload = struct {
    custom_data: []const u8,
};

pub fn main() !void {
    var alg = jwt.algorithms.signature.Hs256{ .secret = "example" };
    const codec = jwt.Codec{
        .sig_algorithm = alg.algorithm(),
    };

    // Encode and print the encoded string
    const payload = ExamplePayload{ .custom_data = "example data" };
    const token = try codec.encode(std.heap.page_allocator, payload);
    std.debug.print("JWT = {s}\n", .{token});

    // Decode and show the decoded parts
    const decoded = try codec.decode(ExamplePayload, std.heap.page_allocator, token);
    std.debug.print(
        "\nDECODED:\nalg = {s}\ntyp = {?s}\ncustom_data = {s}\n",
        .{ decoded.header.alg, decoded.header.typ, decoded.payload.custom_data },
    );
}
