const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/user_settings.h");
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
    @cInclude("wolfssl/wolfcrypt/random.h");
    @cInclude("wolfssl/wolfcrypt/dilithium.h");
});

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

    const msg = args[1];
    const level = try std.fmt.parseInt(u8, args[2], 10);

    // RNG
    var rng: c.WC_RNG = undefined;
    try wcOk(c.wc_InitRng(&rng), "wc_InitRng");
    defer _ = c.wc_FreeRng(&rng);

    // Generate ML-DSA Key Pair
    var key: c.MlDsaKey = undefined;
    try wcOk(c.wc_MlDsaKey_Init(&key, null, c.INVALID_DEVID), "Dilithium key init");
    defer _ = c.wc_MlDsaKey_Free(&key);

    _ = c.wc_MlDsaKey_SetParams(&key, level);
    try wcOk(c.wc_MlDsaKey_MakeKey(&key, &rng), "ML-DSA make key");

    var ml_dsa_pub_len: c_int = 0;
    var ml_dsa_priv_len: c_int = 0;

    try wcOk(c.wc_MlDsaKey_GetPubLen(&key, &ml_dsa_pub_len), "ML-DSA public key length");
    try wcOk(c.wc_MlDsaKey_GetPrivLen(&key, &ml_dsa_priv_len), "ML-DSA private key length");

    // Export public key
    var pk: [4096]u8 = undefined;
    var pub_len: c_uint = pk.len;
    try wcOk(c.wc_MlDsaKey_ExportPubRaw(&key, pk[0..].ptr, &pub_len), "ML-DSA Public Export");
    const pk_bytes = pk[0..@intCast(pub_len)];

    // Export Private Key
    var sk: [16384]u8 = undefined; // reserve enough space for sk
    var sk_len: c_uint = sk.len;
    try wcOk(c.wc_MlDsaKey_ExportPrivRaw(&key, sk[0..].ptr, &sk_len), "ML-DSA Private Export");

    // Sign Message
    var sig_size: usize = @intCast(c.DILITHIUM_LEVEL2_SIG_SIZE);
    if (level == 3) sig_size = @intCast(c.DILITHIUM_LEVEL3_SIG_SIZE);
    if (level == 5) sig_size = @intCast(c.DILITHIUM_LEVEL5_SIG_SIZE);

    const sig = try allocator.alloc(u8, sig_size);
    defer allocator.free(sig);
    const msg_len: c_uint = @intCast(msg.len);
    var sig_len: c_uint = @intCast(sig.len);
    try wcOk(c.wc_MlDsaKey_Sign(&key, sig.ptr, &sig_len, msg.ptr, msg_len, &rng), "sign");

    // Verify signature
    var ver: c_int = 0;
    try wcOk(c.wc_MlDsaKey_Verify(&key, sig.ptr, sig_len, msg, msg_len, &ver), "verify");

    try stdout.print("== ML-DSA Level: {d} ==\n\n", .{level});
    try stdout.print("Message: {s}\n\n", .{msg});
    try stdout.print("Private key (first 200 bytes): {x} Length: {d}\n\n", .{ sk[0..200], sk_len });
    try stdout.print("Public key (first 200 bytes): {x} Length: {d}\n\n", .{ pk_bytes[0..200], ml_dsa_pub_len });
    try stdout.print("Signature (first 200 bytes): {x} Length: {d}\n\n", .{ sig[0..200], sig_len });
    if (ver == 1) try stdout.print("Signature verified\n\n", .{});

    try stdout.flush();
}
