const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
});

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    var data: [*c]u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        data = args[1];
    }

    const len: usize = args[1].len;

    const md5 = c.EVP_get_digestbyname("md5");
    const sha1 = c.EVP_get_digestbyname("sha1");
    const ripemd = c.EVP_get_digestbyname("ripemd");
    const ripemd160 = c.EVP_get_digestbyname("ripemd160");
    const whirlpool = c.EVP_get_digestbyname("whirlpool");
    const mdc2 = c.EVP_get_digestbyname("mdc2");

    const sha256 = c.EVP_get_digestbyname("sha256");
    const sha512 = c.EVP_get_digestbyname("sha512");
    const blake2s256 = c.EVP_get_digestbyname("blake2s256");
    const blake2b512 = c.EVP_get_digestbyname("blake2b512");

    const sha3_256 = c.EVP_get_digestbyname("sha3-256");
    const sha3_512 = c.EVP_get_digestbyname("sha3-512");
    const shake128 = c.EVP_get_digestbyname("shake128");
    const shake256 = c.EVP_get_digestbyname("shake256");

    const sm3 = c.EVP_get_digestbyname("sm3");

    const context = c.EVP_MD_CTX_create();

    const hash_length: [*c]c_uint = 0;

    // MD5
    var md5hash: [16]u8 = undefined;
    _ = c.EVP_DigestInit(context, md5);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &md5hash, hash_length);

    // SHA1
    var sha1hash: [20]u8 = undefined;
    _ = c.EVP_DigestInit(context, sha1);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &sha1hash, hash_length);

    // mdc2
    var mdc2hash: [16]u8 = undefined;
    _ = c.EVP_DigestInit(context, mdc2);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &mdc2hash, hash_length);

    // RIPEMD
    var ripemdhash: [16]u8 = undefined;
    _ = c.EVP_DigestInit(context, ripemd);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &ripemdhash, hash_length);

    // RIPEMD160
    var ripemd160hash: [20]u8 = undefined;
    _ = c.EVP_DigestInit(context, ripemd160);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &ripemd160hash, hash_length);

    // Whirlpool
    var whirlpoolhash: [32]u8 = undefined;
    _ = c.EVP_DigestInit(context, whirlpool);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &whirlpoolhash, hash_length);

    // SHA256
    var sha256hash: [32]u8 = undefined;
    _ = c.EVP_DigestInit(context, sha256);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &sha256hash, hash_length);

    // SHA512
    var sha512hash: [64]u8 = undefined;
    _ = c.EVP_DigestInit(context, sha512);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &sha512hash, hash_length);

    // blake2s256
    var blake2s256hash: [32]u8 = undefined;
    _ = c.EVP_DigestInit(context, blake2s256);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &blake2s256hash, hash_length);

    // blake2b512
    var blake2b512hash: [64]u8 = undefined;
    _ = c.EVP_DigestInit(context, blake2b512);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &blake2b512hash, hash_length);

    // SHA3-256
    var sha3_256hash: [32]u8 = undefined;
    _ = c.EVP_DigestInit(context, sha3_256);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &sha3_256hash, hash_length);

    // SHA3-512
    var sha3_512hash: [32]u8 = undefined;
    _ = c.EVP_DigestInit(context, sha3_512);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &sha3_512hash, hash_length);

    // SM3
    var sm3hash: [32]u8 = undefined;
    _ = c.EVP_DigestInit(context, sm3);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &sm3hash, hash_length);

    // SHAKE128
    var shake128hash: [16]u8 = undefined;
    _ = c.EVP_DigestInit(context, shake128);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &shake128hash, hash_length);

    // SHAKE256
    var shake256hash: [32]u8 = undefined;
    _ = c.EVP_DigestInit(context, shake256);
    _ = c.EVP_DigestUpdate(context, data, len);
    _ = c.EVP_DigestFinal(context, &shake256hash, hash_length);

    try stdout.print("== Hashing with Zig and OpenSSL ==\n", .{});

    try stdout.print("Data:\t\t{s}\n\n", .{data});
    try stdout.print("MD5:\t\t{x}\n", .{md5hash});
    try stdout.print("SHA1:\t\t{x}\n", .{sha1hash});
    try stdout.print("MDC2:\t\t{x}\n", .{mdc2hash});
    try stdout.print("RIPEMD:\t\t{x}\n", .{ripemdhash});
    try stdout.print("RIPEMD160:\t{x}\n", .{ripemd160hash});
    try stdout.print("Whirlpool:\t{x}\n", .{whirlpoolhash});

    try stdout.print("\nSHA256:\t\t{x}\n", .{sha256hash});
    try stdout.print("SHA512:\t\t{x}\n", .{sha512hash});
    try stdout.print("\nBlake2bs256:\t{x}\n", .{blake2s256hash});
    try stdout.print("Blake2bs512:\t{x}\n", .{blake2b512hash});

    try stdout.print("\nSHA3-256:\t{x}\n", .{sha3_256hash});
    try stdout.print("SHA3-512:\t{x}\n", .{sha3_512hash});
    try stdout.print("SHAKE-128:\t{x}\n", .{shake128hash});
    try stdout.print("SHAKE-256:\t{x}\n", .{shake256hash});
    try stdout.print("\nSM3:\t\t{x}\n", .{sm3hash});
    try stdout.flush();
}
