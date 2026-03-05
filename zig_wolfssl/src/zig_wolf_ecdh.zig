// zig build-exe zig_wolf_ecc.zig  C:\home\wolfssl-master\wolfcrypt\src\ecc_wrap.c -lc -IC:\home\wolfssl-master libwolfssl.a  -target x86_64-windows-gnu  -lws2_32
const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
    @cInclude("wolfssl/wolfcrypt/random.h");
});

fn wcOk(rc: c_int, what: []const u8) !void {
    if (rc == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, rc });
    return error.WolfCryptError;
}

const EccKey = opaque {};
extern fn ecc_new() ?*EccKey;
extern fn ecc_delete(k: ?*EccKey) c_int;
extern fn ecc_make_key(k: ?*EccKey, rng: ?*c.WC_RNG) c_int;
extern fn ecc_export_public(k: ?*EccKey, out: [*c]u8, len: [*c]c.word32) c_int;
extern fn ecc_import_public(k: ?*EccKey, input: [*c]const u8, len: c.word32) c_int;
extern fn ecc_shared_secret(priv: ?*EccKey, public: ?*EccKey, out: [*c]u8, len: [*c]c.word32) c_int;
extern fn ecc_export_private_scalar(k: ?*EccKey, out: [*c]u8, outLen: [*c]c.word32) c_int;

pub fn main() !void {
    // const ECC_ECDH_BIT_FIELD = 32;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.15.2 stdout writer pattern
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // RNG
    var rng: c.WC_RNG = undefined;
    try wcOk(c.wc_InitRng(&rng), "wc_InitRng");
    defer _ = c.wc_FreeRng(&rng);

    // Create keys

    const alice = ecc_new() orelse return error.OutOfMemory;
    defer _ = ecc_delete(alice);

    const bob = ecc_new() orelse return error.OutOfMemory;
    defer _ = ecc_delete(bob);

    // Generate ECC keypairs
    try wcOk(ecc_make_key(alice, &rng), "alice key pair");
    try wcOk(ecc_make_key(bob, &rng), "bob key pair");

    // Export public keys
    var alice_pub: [128]u8 = undefined;
    var bob_pub: [128]u8 = undefined;

    var alice_pub_len: c.word32 = alice_pub.len;
    var bob_pub_len: c.word32 = bob_pub.len;

    try wcOk(ecc_export_public(alice, alice_pub[0..].ptr, &alice_pub_len), "export alice pub");
    try wcOk(ecc_export_public(bob, bob_pub[0..].ptr, &bob_pub_len), "export bob pub");

    // Import peer public keys
    const get_alice_public = ecc_new() orelse return error.OutOfMemory;
    defer _ = ecc_delete(get_alice_public);

    const get_bob_public = ecc_new() orelse return error.OutOfMemory;
    defer _ = ecc_delete(get_bob_public);

    try wcOk(ecc_import_public(get_alice_public, bob_pub[0..].ptr, bob_pub_len), "alice import bob");
    try wcOk(ecc_import_public(get_bob_public, alice_pub[0..].ptr, alice_pub_len), "bob import alice");

    // Shared secrets
    var alice_secret: [64]u8 = undefined;
    var bob_secret: [64]u8 = undefined;

    var alice_secret_len: c.word32 = alice_secret.len;
    var bob_secret_len: c.word32 = bob_secret.len;

    try wcOk(ecc_shared_secret(alice, get_alice_public, alice_secret[0..].ptr, &alice_secret_len), "alice secret");
    try wcOk(ecc_shared_secret(bob, get_bob_public, bob_secret[0..].ptr, &bob_secret_len), "bob secret");

    // Export private keys
    var alice_private: [32]u8 = undefined;
    var bob_private: [32]u8 = undefined;

    var alice_private_len: c.word32 = 32;
    var bob_private_len: c.word32 = 32;

    try wcOk(ecc_export_private_scalar(alice, alice_private[0..].ptr, &alice_private_len), "alice export private");
    try wcOk(ecc_export_private_scalar(bob, bob_private[0..].ptr, &bob_private_len), "bob export private");

    try stdout.print("ECDH (P-256)\t\n", .{});
    try stdout.print("Alice's private key:\t{x}\n", .{alice_private[0..32]});
    try stdout.print("Alice's public key:\t{x}\n\n", .{alice_pub[0..alice_pub_len]});

    try stdout.print("Bob's private key:\t{x}\n", .{bob_private[0..32]});
    try stdout.print("Bob's public key:\t\t{x}\n\n", .{bob_pub[0..bob_pub_len]});

    try stdout.print("Alice's shared key:\t{x}\n", .{alice_secret[0..alice_secret_len]});
    try stdout.print("Bob's shared key:\t{x}\n\n", .{bob_secret[0..bob_secret_len]});

    try stdout.flush();
}
