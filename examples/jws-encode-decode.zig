const std = @import("std");
const ziwt = @import("ziwt");

const ExamplePayload = struct {
    custom_data: []const u8,
};

pub fn main() !void {
    var alg = ziwt.algorithms.signature.Hs256{ .secret = "example" };
    const codec = ziwt.jws.Codec{
        .sig_algorithm = alg.algorithm(),
    };

    // Encode and print the encoded string
    const payload = ExamplePayload{ .custom_data = "example data" };
    const jws = try codec.encode(std.heap.page_allocator, payload);
    std.debug.print("JWS = {s}\n", .{jws});

    // Decode and show the decoded parts
    const decoded = try codec.decode(ExamplePayload, std.heap.page_allocator, jws);
    std.debug.print(
        "\nDECODED:\nalg = {s}\ntyp = {?s}\ncustom_data = {s}\n",
        .{ decoded.header.alg, decoded.header.typ, decoded.payload.custom_data },
    );
}
