const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/user_settings.h");
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

// Opaque handle (Zig never sees ecc_key/ecc_point)
const EcdsaKeyHandle = opaque {};
extern fn ecdsa_key_new() ?*EcdsaKeyHandle;
extern fn ecdsa_key_free(h: ?*EcdsaKeyHandle) c_int;
extern fn ecdsa_key_make_p256(h: ?*EcdsaKeyHandle, rng: ?*c.WC_RNG) c_int;
extern fn ecdsa_export_public_x963(h: ?*EcdsaKeyHandle, out: [*c]u8, outLen: [*c]c.word32) c_int;
extern fn ecdsa_export_private_scalar(h: ?*EcdsaKeyHandle, out: [*c]u8, outLen: [*c]c.word32) c_int;
extern fn ecdsa_sign_message(
    h: ?*EcdsaKeyHandle,
    rng: ?*c.WC_RNG,
    msg: [*c]const u8,
    msgLen: c.word32,
    sig: [*c]u8,
    sigLen: [*c]c.word32,
) c_int;

extern fn ecdsa_verify_message(
    h: ?*EcdsaKeyHandle,
    msg: [*c]const u8,
    msgLen: c.word32,
    sig: [*c]const u8,
    sigLen: c.word32,
    verifyRes: [*c]c_int,
) c_int;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.15.2 stdout writer pattern
    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const out = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const msg = args[1];

    // RNG
    var rng: c.WC_RNG = undefined;
    try wcOk(c.wc_InitRng(&rng), "wc_InitRng");
    defer _ = c.wc_FreeRng(&rng);

    // Key handle
    const key = ecdsa_key_new() orelse return error.OutOfMemory;
    defer _ = ecdsa_key_free(key);

    try wcOk(ecdsa_key_make_p256(key, &rng), "Make ECDSA key");

    // Export to a public key using X9.63
    var public: [128]u8 = undefined;
    var pub_len: c.word32 = public.len;
    try wcOk(ecdsa_export_public_x963(key, public[0..].ptr, &pub_len), "Export public key as X963");

    // Export private key (priv)
    var priv: [66]u8 = undefined; // enough for P-256 (32 bytes)
    var priv_len: c.word32 = priv.len;
    try wcOk(ecdsa_export_private_scalar(key, priv[0..].ptr, &priv_len), "Export private key as a scalar");

    // Sign message with DER signature
    var sig: [128]u8 = undefined;
    var sig_len: c.word32 = sig.len;
    try wcOk(
        ecdsa_sign_message(key, &rng, msg.ptr, @intCast(msg.len), sig[0..].ptr, &sig_len),
        "sign message",
    );

    // Verify signature
    var verify_res: c_int = 0;
    try wcOk(
        ecdsa_verify_message(key, msg.ptr, @intCast(msg.len), sig[0..].ptr, sig_len, &verify_res),
        "verify message",
    );

    try out.print("== ECDSA with P-256 and SHA-256 ==\n\n", .{});
    try out.print("Message: {s}\n\n", .{msg});
    try out.print("Private key: {x} Length: {d}\n\n", .{ priv[0..priv_len], priv_len });
    try out.print("Public key: {x} Length: {d}\n\n", .{ public[0..pub_len], pub_len });
    try out.print("Signature: {x} Length: {d}\n\n", .{ sig[0..sig_len], sig_len });
    if (verify_res == 1) try out.print("Signature Verified\n\n", .{});

    try out.flush();
}
