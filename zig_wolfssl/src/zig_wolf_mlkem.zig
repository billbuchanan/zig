const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/wolfcrypt/user_settings.h");

    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
    @cInclude("wolfssl/wolfcrypt/sha3.h");

    @cInclude("wolfssl/wolfcrypt/random.h");
    @cInclude("wolfssl/wolfcrypt/mlkem.h");
});

extern fn mlkem_new(typ: c_int) ?*c.MlKemKey;
extern fn mlkem_delete(k: ?*c.MlKemKey) c_int;

fn wcOk(rc: c_int, what: []const u8) !void {
    if (rc == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, rc });
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

    const level = try std.fmt.parseInt(u8, args[1], 10);

    // RNG
    var rng: c.WC_RNG = undefined;
    try wcOk(c.wc_InitRng(&rng), "wc_InitRng");
    defer _ = c.wc_FreeRng(&rng);

    // Generate ML-KEM Key Pair
    var security = c.WC_ML_KEM_512;
    if (level == 3) security = c.WC_ML_KEM_768;
    if (level == 5) security = c.WC_ML_KEM_1024;
    const AliceKey = mlkem_new(security) orelse return error.OutOfMemory;
    defer _ = mlkem_delete(AliceKey);

    var ss_size: c_uint = 0;

    try wcOk(c.wc_KyberKey_SharedSecretSize(AliceKey, &ss_size), "Shared secret");

    try wcOk(c.wc_MlKemKey_MakeKey(AliceKey, &rng), "Make key");

    // Export public key
    var pub_len: c.word32 = 0;
    try wcOk(c.wc_MlKemKey_PublicKeySize(AliceKey, &pub_len), "PublicKeySize");

    const public = try allocator.alloc(u8, pub_len);
    defer allocator.free(public);

    try wcOk(c.wc_MlKemKey_EncodePublicKey(AliceKey, public.ptr, pub_len), "Encode public");
    try wcOk(c.wc_MlKemKey_DecodePublicKey(AliceKey, public.ptr, pub_len), "Decode public");

    var ct_len: c.word32 = 0;
    try wcOk(c.wc_MlKemKey_CipherTextSize(AliceKey, &ct_len), "CipherTextSize");

    const ct = try allocator.alloc(u8, ct_len);
    defer allocator.free(ct);

    var ss_bob: [c.WC_ML_KEM_SS_SZ]u8 = undefined;
    var ss_alice: [c.WC_ML_KEM_SS_SZ]u8 = undefined;

    try wcOk(c.wc_MlKemKey_Encapsulate(AliceKey, ct.ptr, ss_bob[0..].ptr, &rng), "Encapsulate");

    try wcOk(c.wc_MlKemKey_Decapsulate(AliceKey, ss_alice[0..].ptr, ct.ptr, ct_len), "Decapsulate");

    try stdout.print("== ML-KEM Level: {d} ==\n\n", .{level});
    try stdout.print("Secret Size: {d}\n\n", .{ss_size});
    try stdout.print("Alice Public key (first 100 bytes): {x} Length: {d}\n\n", .{ public[0..100], pub_len });
    try stdout.print("Ciphertext from Bob to Alice (first 100 bytes):\t{x} Length: {d}\n\n", .{ ct[0..100], ct_len });
    try stdout.print("Bob shared secret:\t{x} Length: {d}\n\n", .{ ss_bob, ss_size });
    try stdout.print("Alice shared secret:\t{x} Length: {d}\n\n", .{ ss_alice, ss_size });
    try stdout.flush();
}
