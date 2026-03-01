const std = @import("std");

const c = @cImport({
    // Prefer generated options.h if you have it installed
    @cInclude("wolfssl/wolfcrypt/options.h");

    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
    @cInclude("wolfssl/wolfcrypt/random.h");
    @cInclude("wolfssl/wolfcrypt/sha256.h");
    @cInclude("wolfssl/wolfcrypt/ecc.h");
});

fn wcOk(rc: c_int, what: []const u8) !void {
    if (rc == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, rc });
    return error.WolfCryptError;
}

fn printHex(w: anytype, label: []const u8, data: []const u8) !void {
    try w.print("{s} ({d} bytes): ", .{ label, data.len });
    for (data) |b| try w.print("{x:0>2}", .{b});
    try w.writeByte('\n');
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.15.2 stdout writer pattern (works fine in 0.15.x)
    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const out = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const msg: []const u8 = if (args.len >= 2) args[1] else "Hello ECDSA from Zig + wolfSSL";

    // RNG
    var rng: c.WC_RNG = undefined;
    try wcOk(c.wc_InitRng(&rng), "wc_InitRng");
    defer _ = c.wc_FreeRng(&rng);

    // Generate ECC key (P-256)
    var key: c.ecc_key = undefined;
    try wcOk(c.wc_ecc_init(&key), "wc_ecc_init");
    defer c.wc_ecc_free(&key);

    // size=32 => P-256. (wolfCrypt chooses curve based on size)
    try wcOk(c.wc_ecc_make_key(&rng, 32, &key), "wc_ecc_make_key(P-256)");

    // Hash message with SHA-256 (ECDSA signs hashes)
    var sha: c.Sha256 = undefined;
    try wcOk(c.wc_InitSha256(&sha), "wc_InitSha256");
    defer _ = c.wc_Sha256Free(&sha);

    try wcOk(c.wc_Sha256Update(&sha, msg.ptr, @intCast(msg.len)), "wc_Sha256Update");

    var digest: [c.SHA256_DIGEST_SIZE]u8 = undefined;
    try wcOk(c.wc_Sha256Final(&sha, &digest), "wc_Sha256Final");

    // Sign digest. Allocate a buffer big enough for DER signature.
    // For P-256, 80 bytes is safely above the max DER-encoded ECDSA signature size.
    var sig: [80]u8 = undefined;
    var sig_len: c.word32 = sig.len;

    try wcOk(
        c.wc_ecc_sign_hash(digest[0..].ptr, digest.len, &sig, &sig_len, &rng, &key),
        "wc_ecc_sign_hash",
    );

    // Verify
    var verify_res: c_int = 0;
    try wcOk(
        c.wc_ecc_verify_hash(sig[0..sig_len].ptr, sig_len, digest[0..].ptr, digest.len, &verify_res, &key),
        "wc_ecc_verify_hash",
    );

    try out.print("Message: {s}\n", .{msg});
    try out.print("Verify: {s}\n\n", .{if (verify_res == 1) "OK" else "FAIL"});
    try printHex(out, "SHA-256(msg)", digest[0..]);
    try printHex(out, "ECDSA signature (DER)", sig[0..@intCast(sig_len)]);

    try out.flush();
}
