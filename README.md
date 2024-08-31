# ziwt
Zig JSON Web Token package.

# Example

```zig
const std = @import("std");
const ziwt = @import("ziwt");

const ExamplePayload = struct {
    custom_data: []const u8,
};

pub fn main() !void {
    var alg = ziwt.algorithms.signature.Hs256{ .secret = "example" };
    const codec = ziwt.Codec{
        .sig_algorithm = alg.algorithm(),
    };

    // Encode and print the encoded string
    const payload = ExamplePayload{ .custom_data = "example data" };
    const jwt = try codec.encode(std.heap.page_allocator, payload);
    std.debug.print("JWT = {s}\n", .{jwt});

    // Decode and show the decoded parts
    const decoded = try codec.decode(ExamplePayload, std.heap.page_allocator, jwt);
    std.debug.print(
        "\nDECODED:\nalg = {s}\ntyp = {?s}\ncustom_data = {s}\n",
        .{ decoded.header.alg, decoded.header.typ, decoded.payload.custom_data },
    );
}

```
