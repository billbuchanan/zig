const std = @import("std");
const crypto = std.crypto.hash;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

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

    var Blake2b128: [crypto.blake2.Blake2b128.digest_length]u8 = undefined;
    var Blake2b160: [crypto.blake2.Blake2b160.digest_length]u8 = undefined;
    var Blake2b256: [crypto.blake2.Blake2b256.digest_length]u8 = undefined;
    var Blake2b384: [crypto.blake2.Blake2b384.digest_length]u8 = undefined;
    var Blake2b512: [crypto.blake2.Blake2b512.digest_length]u8 = undefined;
    var Blake2s128: [crypto.blake2.Blake2s128.digest_length]u8 = undefined;
    var Blake2s160: [crypto.blake2.Blake2s160.digest_length]u8 = undefined;
    var Blake2s256: [crypto.blake2.Blake2s256.digest_length]u8 = undefined;

    var hash224: [crypto.sha2.Sha224.digest_length]u8 = undefined;
    var hash256: [crypto.sha2.Sha256.digest_length]u8 = undefined;
    var hash384: [crypto.sha2.Sha384.digest_length]u8 = undefined;
    var hash512: [crypto.sha2.Sha512.digest_length]u8 = undefined;

    var Blake3v: [crypto.Blake3.digest_length]u8 = undefined;
    var MD5: [crypto.Md5.digest_length]u8 = undefined;
    var SHA1: [crypto.Sha1.digest_length]u8 = undefined;

    var SHA3_Keccak256: [crypto.sha3.Keccak256.digest_length]u8 = undefined;
    var SHA3_Keccak512: [crypto.sha3.Keccak512.digest_length]u8 = undefined;

    var Sha3_224: [crypto.sha3.Sha3_224.digest_length]u8 = undefined;
    var Sha3_256: [crypto.sha3.Sha3_256.digest_length]u8 = undefined;
    var Sha3_384: [crypto.sha3.Sha3_384.digest_length]u8 = undefined;
    var Sha3_512: [crypto.sha3.Sha3_512.digest_length]u8 = undefined;

    crypto.Blake3.hash(data, &Blake3v, .{});
    crypto.Md5.hash(data, &MD5, .{});
    crypto.Sha1.hash(data, &SHA1, .{});

    crypto.sha3.Keccak256.hash(data, &SHA3_Keccak256, .{});
    crypto.sha3.Keccak512.hash(data, &SHA3_Keccak512, .{});

    crypto.sha3.Sha3_224.hash(data, &Sha3_224, .{});
    crypto.sha3.Sha3_256.hash(data, &Sha3_256, .{});
    crypto.sha3.Sha3_384.hash(data, &Sha3_384, .{});
    crypto.sha3.Sha3_512.hash(data, &Sha3_512, .{});

    crypto.blake2.Blake2b128.hash(data, &Blake2b128, .{});
    crypto.blake2.Blake2b160.hash(data, &Blake2b160, .{});
    crypto.blake2.Blake2b256.hash(data, &Blake2b256, .{});
    crypto.blake2.Blake2b384.hash(data, &Blake2b384, .{});
    crypto.blake2.Blake2b512.hash(data, &Blake2b512, .{});

    crypto.blake2.Blake2s128.hash(data, &Blake2s128, .{});
    crypto.blake2.Blake2s160.hash(data, &Blake2s160, .{});
    crypto.blake2.Blake2s256.hash(data, &Blake2s256, .{});

    crypto.sha2.Sha224.hash(data, &hash224, .{});
    crypto.sha2.Sha256.hash(data, &hash256, .{});
    crypto.sha2.Sha384.hash(data, &hash384, .{});
    crypto.sha2.Sha512.hash(data, &hash512, .{});

    try stdout.print("MD5 {x}\n", .{MD5});
    try stdout.print("SHA1 {x}\n", .{SHA1});

    try stdout.print("\nSHA3 Keccak256 {x}\n", .{SHA3_Keccak256});
    try stdout.print("SHA3 Keccak512 {x}\n", .{SHA3_Keccak512});
    try stdout.print("SHA3-224 {x}\n", .{Sha3_224});
    try stdout.print("SHA3-256 {x}\n", .{Sha3_256});
    try stdout.print("SHA3-384 {x}\n", .{Sha3_384});
    try stdout.print("SHA3-512 {x}\n", .{Sha3_512});

    try stdout.print("\nSHA-224 {x}\n", .{hash224});
    try stdout.flush();
    try stdout.print("SHA-256 {x}\n", .{hash256});
    try stdout.flush();
    try stdout.print("SHA-384 {x}\n", .{hash384});
    try stdout.flush();
    try stdout.print("SHA-512 {x}\n", .{hash512});
    try stdout.flush();

    try stdout.print("\nBlake3 {x}\n", .{Blake3v});
    try stdout.print("Blake2b128 {x}\n", .{Blake2b128});

    try stdout.print("Blake2b160 {x}\n", .{Blake2b160});

    try stdout.print("Blake2b256 {x}\n", .{Blake2b256});

    try stdout.print("Blake2b384 {x}\n", .{Blake2b384});

    try stdout.print("Blake2b512 {x}\n", .{Blake2b512});

    try stdout.print("Blake2s128 {x}\n", .{Blake2s128});

    try stdout.print("Blake2s160 {x}\n", .{Blake2s160});

    try stdout.print("Blake2s256 {x}\n", .{Blake2s256});
    try stdout.flush();
}
