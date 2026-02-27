const crypto = std.crypto;
const std = @import("std");

fn u64ToBytes32BE(x: u64) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;

    // Write x into out[24..32] as big-endian
    out[24] = @intCast((x >> 56) & 0xff);
    out[25] = @intCast((x >> 48) & 0xff);
    out[26] = @intCast((x >> 40) & 0xff);
    out[27] = @intCast((x >> 32) & 0xff);
    out[28] = @intCast((x >> 24) & 0xff);
    out[29] = @intCast((x >> 16) & 0xff);
    out[30] = @intCast((x >> 8) & 0xff);
    out[31] = @intCast((x >> 0) & 0xff);

    return out;
}
pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    var seedvalstr: []const u8 = undefined;

    // Check if there are any arguments
    if (args.len > 1) {
        seedvalstr = args[1];
    }
    const seedval = try std.fmt.parseInt(u64, seedvalstr, 10);

    try stdout.print("Seed:\t{}\n\n", .{seedval});

    var prng = std.Random.DefaultPrng.init(seedval); // Initialize the pseudo-random number generator
    var rval = prng.random();
    var r1 = rval.int(u64);
    var r2 = rval.int(u64);
    try stdout.print("First two Xoshiro256:\t{}, {}\n", .{ r1, r2 });

    var seed: [32]u8 = undefined;

    seed = u64ToBytes32BE(seedval);

    var prng1 = std.Random.Ascon.init(seed); // Initialize the pseudo-random number generator
    rval = prng1.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two Ascon:\t{}, {}\n", .{ r1, r2 });

    var prng2 = std.Random.Isaac64.init(seedval); // Initialize the pseudo-random number generator
    rval = prng2.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two Isac64:\t{}, {}\n", .{ r1, r2 });

    var prng3 = std.Random.ChaCha.init(seed); // Initialize the pseudo-random number generator
    rval = prng3.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two ChaCha:\t{}, {}\n", .{ r1, r2 });

    var prng4 = std.Random.Pcg.init(seedval); // Initialize the pseudo-random number generator
    rval = prng4.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two Pcg:\t\t{}, {}\n", .{ r1, r2 });

    var prng5 = std.Random.Xoroshiro128.init(seedval); // Initialize the pseudo-random number generator
    rval = prng5.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two Xoroshiro128:\t{}, {}\n", .{ r1, r2 });

    var prng6 = std.Random.Xoshiro256.init(seedval); // Initialize the pseudo-random number generator
    rval = prng6.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two Xoshiro256:\t{}, {}\n", .{ r1, r2 });

    var prng7 = std.Random.Sfc64.init(seedval); // Initialize the pseudo-random number generator
    rval = prng7.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two Sfc64:\t{}, {}\n", .{ r1, r2 });

    var prng8 = std.Random.RomuTrio.init(seedval); // Initialize the pseudo-random number generator
    rval = prng8.random();
    r1 = rval.int(u64);
    r2 = rval.int(u64);
    try stdout.print("First two RomuTrio:\t{}, {}\n", .{ r1, r2 });

    var prng9 = std.Random.SplitMix64.init(seedval); // Initialize the pseudo-random number generator
    r1 = prng9.next();
    r2 = prng9.next();
    try stdout.print("First two SplitMix64:\t{}, {}\n", .{ r1, r2 });

    //   const r = std.Random.ziggurat.exp_f(0.0); // Initialize the pseudo-random number generator
    //   try stdout.print("Ziggurat: {}", .{r});

    try stdout.flush();
}
