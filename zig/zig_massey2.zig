const crypto = std.crypto;
const std = @import("std");

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

    var prng = std.Random.DefaultPrng.init(seedval); // Initialize the pseudo-random number generator
    var rval = prng.random();
    var r1 = rval.int(u64);
    var r2 = rval.int(u64);
    try stdout.print("First two Xoshiro256:\t{}, {}\n", .{ r1, r2 });

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);

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
    try stdout.print("First two Ascon:\t{}, {}\n", .{ r1, r2 });

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
