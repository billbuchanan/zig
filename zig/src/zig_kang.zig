const std = @import("std");
const crypto = std.crypto.hash;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Create keys for KMac
    var key256: [32]u8 = undefined;
    var key128: [16]u8 = undefined;

    // Fill 'key' with a secure random key
    std.crypto.random.bytes(&key256);
    std.crypto.random.bytes(&key128);

    // Get the command-line arguments

    var data: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        data = args[1];
    }

    try stdout.print("Hashing: {s}\n", .{data});
    try stdout.flush();

    var KT128: [crypto.sha3.KT128.digest_length]u8 = undefined;
    var KT256: [crypto.sha3.KT256.digest_length]u8 = undefined;
    var CShake128: [crypto.sha3.CShake128.digest_length]u8 = undefined;
    var CShake256: [crypto.sha3.CShake256.digest_length]u8 = undefined;
    var KMac128: [crypto.sha3.KT128.digest_length]u8 = undefined;
    var KMac256: [crypto.sha3.KT256.digest_length]u8 = undefined;
    var Shake128: [crypto.sha3.Shake128.digest_length]u8 = undefined;
    var Shake256: [crypto.sha3.Shake256.digest_length]u8 = undefined;
    var Keccak256: [crypto.sha3.Keccak256.digest_length]u8 = undefined;
    var Keccak512: [crypto.sha3.Keccak512.digest_length]u8 = undefined;

    var Sha3_224: [crypto.sha3.Sha3_224.digest_length]u8 = undefined;
    var Sha3_256: [crypto.sha3.Sha3_256.digest_length]u8 = undefined;
    var Sha3_384: [crypto.sha3.Sha3_384.digest_length]u8 = undefined;
    var Sha3_512: [crypto.sha3.Sha3_512.digest_length]u8 = undefined;

    const TupleHash128: [crypto.sha3.TupleHash128.digest_length]u8 = undefined;
    const TupleHash256: [crypto.sha3.TupleHash256.digest_length]u8 = undefined;

    try crypto.sha3.KT128.hash(data, &KT128, .{});
    try crypto.sha3.KT256.hash(data, &KT256, .{});
    crypto.sha3.CShake128.hash(data, &CShake128, .{});
    crypto.sha3.CShake256.hash(data, &CShake256, .{});
    crypto.sha3.KMac128.create(&KMac128, data, &key128);
    crypto.sha3.KMac256.create(&KMac256, data, &key256);
    crypto.sha3.Shake128.hash(data, &Shake128, .{});
    crypto.sha3.Shake256.hash(data, &Shake256, .{});

    crypto.sha3.Keccak256.hash(data, &Keccak256, .{});
    crypto.sha3.Keccak512.hash(data, &Keccak512, .{});

    crypto.sha3.Sha3_224.hash(data, &Sha3_224, .{});
    crypto.sha3.Sha3_256.hash(data, &Sha3_256, .{});
    crypto.sha3.Sha3_384.hash(data, &Sha3_384, .{});
    crypto.sha3.Sha3_512.hash(data, &Sha3_512, .{});

    //    crypto.sha3.TupleHash128.(data, &TupleHash128, .{});
    //    crypto.sha3.TupleHash256.hash(data, &TupleHash256, .{});

    try stdout.print("Kangaroo 12 (128) {x}\n", .{KT128});
    try stdout.print("Kangaroo 12 (256) {x}\n", .{KT256});
    try stdout.print("\nCShake128 (128) {x}\n", .{CShake128});
    try stdout.print("CShake256 {x}\n", .{CShake256});
    try stdout.print("\nKMac128 {x}\n", .{KMac128});
    try stdout.print("KMac256 {x}\n", .{KMac256});
    try stdout.print("\nShake128 {x}\n", .{Shake128});
    try stdout.print("Shake256 {x}\n", .{Shake256});
    try stdout.print("\nKeccak256 {x}\n", .{Keccak256});
    try stdout.print("Keccak512 {x}\n", .{Keccak512});

    try stdout.print("\nSha3_224 {x}\n", .{Sha3_224});
    try stdout.print("Sha3_256 {x}\n", .{Sha3_256});
    try stdout.print("Sha3_384 {x}\n", .{Sha3_384});
    try stdout.print("Sha3_512 {x}\n", .{Sha3_512});

    try stdout.print("\nTupleHash128 {x}\n", .{TupleHash128});
    try stdout.print("TupleHash256 {x}\n", .{TupleHash256});

    try stdout.flush();
}
