const std = @import("std");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    const msg = "hello";

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(msg);

    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    for (digest) |b| {
        try stdout.print("{x:0>2}", .{b});
    }
    try stdout.print("\n", .{});
}