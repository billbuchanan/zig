// cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DWOLFSSL_RIPEMD=ON -DWOLFSSL_SM3=ON -DWOLFSSL_USER_SETTINGS=yes ..
const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/options.h");
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");

    // Classic hashes
    @cInclude("wolfssl/wolfcrypt/md4.h");
    @cInclude("wolfssl/wolfcrypt/md5.h");
    @cInclude("wolfssl/wolfcrypt/sha.h");
    @cInclude("wolfssl/wolfcrypt/sha256.h");
    @cInclude("wolfssl/wolfcrypt/sha512.h");

    @cInclude("wolfssl/wolfcrypt/ripemd.h");
    // SHA-3 + SHAKE
    @cInclude("wolfssl/wolfcrypt/sha3.h");
    @cInclude("wolfssl/wolfcrypt/blake2.h");
});

fn testOkay(ret: c_int, what: []const u8) !void {
    if (ret == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, ret });
    return error.WolfCryptError;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.15.2 stdout writer pattern
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const msg = args[1];

    try stdout.print("Message: {s}\n\n", .{msg});

    var md4: c.Md4 = undefined;
    var md4_out: [c.MD4_DIGEST_SIZE]u8 = undefined;
    _ = c.wc_InitMd4(&md4);
    _ = c.wc_Md4Update(&md4, msg.ptr, @intCast(msg.len));
    _ = c.wc_Md4Final(&md4, &md4_out);

    var md5: c.Md5 = undefined;
    defer _ = c.wc_Md5Free(&md5);
    var md5_out: [c.MD5_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_InitMd5(&md5), "wc_Initmd5");
    try testOkay(c.wc_Md5Update(&md5, msg.ptr, @intCast(msg.len)), "wc_md5Update");
    try testOkay(c.wc_Md5Final(&md5, &md5_out), "wc_Md5Final");

    var ripemd: c.RipeMd = undefined;
    // defer _ = c.wc_RipeMdFree(&ripemd);
    var ripemd_out: [c.RIPEMD_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_InitRipeMd(&ripemd), "wc_InitRipem160");
    try testOkay(c.wc_RipeMdUpdate(&ripemd, msg.ptr, @intCast(msg.len)), "wc_md5Update");
    try testOkay(c.wc_RipeMdFinal(&ripemd, &ripemd_out), "wc_RipmeFinal");

    // ---------------- SHA-1 ----------------
    var sha1: c.Sha = undefined;
    defer _ = c.wc_ShaFree(&sha1);
    try testOkay(c.wc_InitSha(&sha1), "wc_InitSha");
    var sha1_out: [c.SHA_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_ShaUpdate(&sha1, msg.ptr, @intCast(msg.len)), "wc_ShaUpdate");
    try testOkay(c.wc_ShaFinal(&sha1, &sha1_out), "wc_ShaFinal");

    // ---------------- SHA-224 / SHA-256 ----------------
    var sha224: c.Sha224 = undefined;
    defer _ = c.wc_Sha224Free(&sha224);
    var sha224_out: [c.SHA224_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_InitSha224(&sha224), "wc_InitSha224");
    try testOkay(c.wc_Sha224Update(&sha224, msg.ptr, @intCast(msg.len)), "wc_Sha224Update");
    try testOkay(c.wc_Sha224Final(&sha224, &sha224_out), "wc_Sha224Final");

    var sha256: c.Sha256 = undefined;
    defer _ = c.wc_Sha256Free(&sha256);
    var sha256_out: [c.SHA256_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_InitSha256(&sha256), "wc_InitSha256");
    try testOkay(c.wc_Sha256Update(&sha256, msg.ptr, @intCast(msg.len)), "wc_Sha256Update");
    try testOkay(c.wc_Sha256Final(&sha256, &sha256_out), "wc_Sha256Final");

    var sha512: c.Sha512 = undefined;
    defer _ = c.wc_Sha512Free(&sha512);
    var sha512_out: [c.SHA512_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_InitSha512(&sha512), "wc_Initsha512");
    try testOkay(c.wc_Sha512Update(&sha512, msg.ptr, @intCast(msg.len)), "wc_Sha512Update");
    try testOkay(c.wc_Sha512Final(&sha512, &sha512_out), "wc_Sha512Final");

    // ---------------- SHA3-224/256/384/512 ----------------
    var s3_224: c.Sha3 = undefined;
    // defer _ = c.wc_Sha3_Free(&s3_224);
    var out224: [28]u8 = undefined;
    try testOkay(c.wc_InitSha3_224(&s3_224, null, c.INVALID_DEVID), "wc_InitSha3_224");
    try testOkay(c.wc_Sha3_224_Update(&s3_224, msg.ptr, @intCast(msg.len)), "wc_Sha3_224_Update");
    try testOkay(c.wc_Sha3_224_Final(&s3_224, &out224), "wc_Sha3_224_Final");

    var s3_256: c.Sha3 = undefined;
    // defer _ = c.wc_Sha3_Free(&s3_256);
    var out256: [32]u8 = undefined;
    try testOkay(c.wc_InitSha3_256(&s3_256, null, c.INVALID_DEVID), "wc_InitSha3_256");
    try testOkay(c.wc_Sha3_256_Update(&s3_256, msg.ptr, @intCast(msg.len)), "wc_Sha3_256_Update");
    try testOkay(c.wc_Sha3_256_Final(&s3_256, &out256), "wc_Sha3_256_Final");

    var s3_384: c.Sha3 = undefined;
    // defer _ = c.wc_Sha3_Free(&s3_384);
    var out384: [48]u8 = undefined;
    try testOkay(c.wc_InitSha3_384(&s3_384, null, c.INVALID_DEVID), "wc_InitSha3_384");
    try testOkay(c.wc_Sha3_384_Update(&s3_384, msg.ptr, @intCast(msg.len)), "wc_Sha3_384_Update");
    try testOkay(c.wc_Sha3_384_Final(&s3_384, &out384), "wc_Sha3_384_Final");

    var s3_512: c.Sha3 = undefined;
    // defer _ = c.wc_Sha3_Free(&s3_512);
    var out512: [64]u8 = undefined;
    try testOkay(c.wc_InitSha3_512(&s3_512, null, c.INVALID_DEVID), "wc_InitSha3_512");
    try testOkay(c.wc_Sha3_512_Update(&s3_512, msg.ptr, @intCast(msg.len)), "wc_Sha3_512_Update");
    try testOkay(c.wc_Sha3_512_Final(&s3_512, &out512), "wc_Sha3_512_Final");

    var blake2b: c.Blake2b = undefined;
    // defer _ = c.wc_Sha3_Free(&s3_512);
    var outblake2b: [c.WC_BLAKE2B_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_InitBlake2b(&blake2b, c.WC_BLAKE2B_DIGEST_SIZE), "wc_InitBake2b");
    try testOkay(c.wc_Blake2bUpdate(&blake2b, msg.ptr, @intCast(msg.len)), "wc_wc_InitBake2b_Update");
    try testOkay(c.wc_Blake2bFinal(&blake2b, &outblake2b, c.WC_BLAKE2B_DIGEST_SIZE), "wc_wc_InitBake2b_Final");

    var blake2s: c.Blake2s = undefined;
    // defer _ = c.wc_Sha3_Free(&s3_512);
    var outblake2s: [c.WC_BLAKE2S_DIGEST_SIZE]u8 = undefined;
    try testOkay(c.wc_InitBlake2s(&blake2s, c.WC_BLAKE2S_DIGEST_SIZE), "wc_InitBake2s");
    try testOkay(c.wc_Blake2sUpdate(&blake2s, msg.ptr, @intCast(msg.len)), "wc_wc_InitBake2s_Update");
    try testOkay(c.wc_Blake2sFinal(&blake2s, &outblake2s, c.WC_BLAKE2S_DIGEST_SIZE), "wc_wc_InitBake2s_Final");

    try stdout.print("MD4:\t\t{x}\n", .{md4_out[0..]});
    try stdout.print("MD5:\t\t{x}\n", .{md5_out[0..]});
    try stdout.print("SHA-1:\t\t{x}\n", .{sha1_out[0..]});
    try stdout.print("SHA-224:\t{x}\n", .{sha224_out[0..]});
    try stdout.print("SHA-256:\t{x}\n", .{sha256_out[0..]});
    try stdout.print("SHA-512:\t{x}\n", .{sha512_out[0..]});
    try stdout.print("SHA3-224:\t{x}\n", .{out224[0..]});
    try stdout.print("SHA3-256:\t{x}\n", .{out256[0..]});
    try stdout.print("SHA3-384:\t{x}\n", .{out384[0..]});
    try stdout.print("SHA3-512:\t{x}\n", .{out512[0..]});
    try stdout.print("RIPEMD:\t\t{x}\n", .{ripemd_out[0..]});
    try stdout.print("Blake2b:\t{x}\n", .{outblake2b[0..]});
    try stdout.print("Blake2s:\t{x}\n", .{outblake2s[0..]});

    try stdout.flush();
}
