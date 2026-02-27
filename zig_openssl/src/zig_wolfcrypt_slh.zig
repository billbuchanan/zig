const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/sha.h");
    @cInclude("wolfssl/wolfcrypt/sha256.h");
    @cInclude("wolfssl/wolfcrypt/sha512.h");
    @cInclude("wolfssl/wolfcrypt/sha3.h");
    @cInclude("wolfssl/wolfcrypt/blake2.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
});

fn wcCheck(ret: c_int, what: []const u8) !void {
    if (ret == 0) return;
    std.debug.print("{s} failed: ret={d}\n", .{ what, ret });
    return error.WolfCryptError;
}

fn printHex(writer: anytype, label: []const u8, data: []const u8) !void {
    try writer.print("{s} ({d} bytes): ", .{ label, data.len });
    for (data) |b| try writer.print("{x:0>2}", .{b});
    try writer.writeByte('\n');
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Zig 0.15.2 stdout writer pattern
    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer = std.Io.stdout.writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Message from CLI (or default)
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const msg: []const u8 = if (args.len >= 2) args[1] else "Hello from Zig + wolfCrypt";

    // SHA-1
    var sha1: c.Sha = undefined;
    try wcCheck(c.wc_InitSha(&sha1), "wc_InitSha");
    defer _ = c.wc_ShaFree(&sha1);
    try wcCheck(c.wc_ShaUpdate(&sha1, msg.ptr, @intCast(c.word32, msg.len)), "wc_ShaUpdate");
    var sha1_out: [c.SHA_DIGEST_SIZE]u8 = undefined;
    try wcCheck(c.wc_ShaFinal(&sha1, &sha1_out), "wc_ShaFinal");

    // SHA-256
    var sha256: c.Sha256 = undefined;
    try wcCheck(c.wc_InitSha256(&sha256), "wc_InitSha256");
    defer _ = c.wc_Sha256Free(&sha256);
    try wcCheck(c.wc_Sha256Update(&sha256, msg.ptr, @intCast(c.word32, msg.len)), "wc_Sha256Update");
    var sha256_out: [c.SHA256_DIGEST_SIZE]u8 = undefined;
    try wcCheck(c.wc_Sha256Final(&sha256, &sha256_out), "wc_Sha256Final");

    // SHA-512
    var sha512: c.Sha512 = undefined;
    try wcCheck(c.wc_InitSha512(&sha512), "wc_InitSha512");
    defer _ = c.wc_Sha512Free(&sha512);
    try wcCheck(c.wc_Sha512Update(&sha512, msg.ptr, @intCast(c.word32, msg.len)), "wc_Sha512Update");
    var sha512_out: [c.SHA512_DIGEST_SIZE]u8 = undefined;
    try wcCheck(c.wc_Sha512Final(&sha512, &sha512_out), "wc_Sha512Final");

    // SHA3-256
    var sha3_256: c.Sha3 = undefined;
    try wcCheck(c.wc_InitSha3_256(&sha3_256, null, c.INVALID_DEVID), "wc_InitSha3_256");
    defer _ = c.wc_Sha3_Free(&sha3_256);
    try wcCheck(c.wc_Sha3_256_Update(&sha3_256, msg.ptr, msg.len), "wc_Sha3_256_Update");
    var sha3_256_out: [32]u8 = undefined;
    try wcCheck(c.wc_Sha3_256_Final(&sha3_256, &sha3_256_out), "wc_Sha3_256_Final");

    // SHA3-512
    var sha3_512: c.Sha3 = undefined;
    try wcCheck(c.wc_InitSha3_512(&sha3_512, null, c.INVALID_DEVID), "wc_InitSha3_512");
    defer _ = c.wc_Sha3_Free(&sha3_512);
    try wcCheck(c.wc_Sha3_512_Update(&sha3_512, msg.ptr, msg.len), "wc_Sha3_512_Update");
    var sha3_512_out: [64]u8 = undefined;
    try wcCheck(c.wc_Sha3_512_Final(&sha3_512, &sha3_512_out), "wc_Sha3_512_Final");

    // BLAKE2b-512 (wolfCrypt "Blake2b")
    var b2b: c.Blake2b = undefined;
    try wcCheck(c.wc_InitBlake2b(&b2b, 64), "wc_InitBlake2b");
    try wcCheck(c.wc_Blake2bUpdate(&b2b, msg.ptr, msg.len), "wc_Blake2bUpdate");
    var b2b_out: [64]u8 = undefined;
    try wcCheck(c.wc_Blake2bFinal(&b2b, &b2b_out, 64), "wc_Blake2bFinal");

    try stdout.print("Message: {s}\n\n", .{msg});
    try printHex(stdout, "SHA-1", sha1_out[0..]);
    try printHex(stdout, "SHA-256", sha256_out[0..]);
    try printHex(stdout, "SHA-512", sha512_out[0..]);
    try printHex(stdout, "SHA3-256", sha3_256_out[0..]);
    try printHex(stdout, "SHA3-512", sha3_512_out[0..]);
    try printHex(stdout, "BLAKE2b-512", b2b_out[0..]);

    try stdout.flush();
}