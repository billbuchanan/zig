const std = @import("std");
const crypto = @import("std").crypto;

pub fn uintTo32Bytes(comptime T: type, value: T) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    var v = value;

    var i: usize = 0;
    while (v != 0 and i < 32) : (i += 1) {
        out[31 - i] = @intCast(v & 0xff);
        v >>= 8;
    }

    return out;
}
pub fn main() !void {
    var message: []u8 = undefined;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    const seed: u32 = 123;
    var seed32: [32]u8 = undefined;

    seed32 = uintTo32Bytes(u32, seed);

    var prng = std.Random.Ascon.init(seed32);

    const rng = prng.random();

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const val = rng.int(u32);
        try stdout.print("random i32[{d}]: {d}\n", .{ i, val });
    }
    prng.


    try stdout.flush();
}
