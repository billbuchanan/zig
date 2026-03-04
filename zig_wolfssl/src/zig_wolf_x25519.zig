// zig build-exe zig_wolf_x25519.zig  C:\home\wolfssl-master\wolfcrypt\src\x25519_wrap.c -lc -IC:\home\wolfssl-master libwolfssl.a  -target x86_64-windows-gnu  -lws2_32
const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
    @cInclude("wolfssl/wolfcrypt/curve25519.h");
});

fn wcOk(rc: c_int, what: []const u8) !void {
    if (rc == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, rc });
    return error.WolfCryptError;
}
extern fn x25519_new() ?*c.curve25519_key;
extern fn x25519_delete(k: ?*c.curve25519_key) c_int;
extern fn x25519_make_key(k: ?*c.curve25519_key, rng: ?*c.WC_RNG) c_int;
extern fn x25519_export_public(k: ?*c.curve25519_key, out32: [*c]u8, outLen: [*c]c.word32) c_int;
extern fn x25519_import_public(k: ?*c.curve25519_key, in32: [*c]const u8, inLen: c.word32) c_int;
extern fn x25519_shared_secret(myPriv: ?*c.curve25519_key, theirPub: ?*c.curve25519_key, out: [*c]u8, outLen: [*c]c.word32) c_int;
extern fn x25519_export_private(
    k: ?*c.curve25519_key,
    out: [*c]u8,
    len: [*c]c.word32,
) c_int;

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

    // RNG
    var rng: c.WC_RNG = undefined;
    try wcOk(c.wc_InitRng(&rng), "wc_InitRng");
    defer _ = c.wc_FreeRng(&rng);

    // Create Alice and Bob key pairs
    const alice = x25519_new() orelse return error.OutOfMemory;
    defer _ = x25519_delete(alice);

    const bob = x25519_new() orelse return error.OutOfMemory;
    defer _ = x25519_delete(bob);

    try wcOk(x25519_make_key(alice, &rng), "alice make key");
    try wcOk(x25519_make_key(bob, &rng), "bob make key");

    // Export public keys
    var alice_public: [32]u8 = undefined;
    var bob_public: [32]u8 = undefined;

    var alice_public_len: c.word32 = 32;
    var bob_public_len: c.word32 = 32;

    try wcOk(x25519_export_public(alice, alice_public[0..].ptr, &alice_public_len), "export alice pub");
    try wcOk(x25519_export_public(bob, bob_public[0..].ptr, &bob_public_len), "export bob pub");

    // Import keys
    const get_alice_public = x25519_new() orelse return error.OutOfMemory;
    defer _ = x25519_delete(get_alice_public);

    const get_bob_public = x25519_new() orelse return error.OutOfMemory;
    defer _ = x25519_delete(get_bob_public);

    try wcOk(x25519_import_public(get_alice_public, bob_public[0..].ptr, bob_public_len), "alice import bob");
    try wcOk(x25519_import_public(get_bob_public, alice_public[0..].ptr, alice_public_len), "bob import alice");

    // Compute shared secret
    var alice_secret: [32]u8 = undefined;
    var bob_secret: [32]u8 = undefined;

    var alice_secret_len: c.word32 = 32;
    var bob_secret_len: c.word32 = 32;

    try wcOk(x25519_shared_secret(alice, get_alice_public, alice_secret[0..].ptr, &alice_secret_len), "alice secret");
    try wcOk(x25519_shared_secret(bob, get_bob_public, bob_secret[0..].ptr, &bob_secret_len), "bob secret");

    // Export private keys
    var alice_private: [32]u8 = undefined;
    var bob_private: [32]u8 = undefined;

    var alice_private_len: c.word32 = 32;
    var bob_private_len: c.word32 = 32;

    try wcOk(x25519_export_private(alice, alice_private[0..].ptr, &alice_private_len), "alice export private");
    try wcOk(x25519_export_private(bob, bob_private[0..].ptr, &bob_private_len), "bob export private");

    try stdout.print("== X25519 ==\n\n", .{});
    try stdout.print("Alice private key:\t{x}\n", .{alice_private[0..alice_private_len]});
    try stdout.print("Alice public key:\t{x}\n\n", .{alice_public[0..alice_public_len]});

    try stdout.print("Bob private key:\t{x}\n", .{bob_private[0..bob_private_len]});
    try stdout.print("Bob public key:\t\t{x}\n\n", .{bob_public[0..bob_public_len]});

    try stdout.print("Bob shared key:\t\t{x} \n", .{bob_secret[0..bob_secret_len]});
    try stdout.print("Alice shared key:\t{x}\n\n", .{alice_secret[0..alice_secret_len]});
    try stdout.flush();
}
