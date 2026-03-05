// zig build-exe zig_wolf_curve448.zig  C:\home\wolfssl-master\wolfcrypt\src\curve448_wrap.c -lc -IC:\home\wolfssl-master libwolfssl.a  -target x86_64-windows-gnu  -lws2_32
const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
    @cInclude("wolfssl/wolfcrypt/curve448.h");
    @cInclude("wolfssl/wolfcrypt/random.h");
});

fn wcOk(rc: c_int, what: []const u8) !void {
    if (rc == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, rc });
    return error.WolfCryptError;
}
extern fn curve448_new() ?*c.curve448_key;
extern fn curve448_delete(k: ?*c.curve448_key) c_int;
extern fn curve448_make_key(k: ?*c.curve448_key, rng: ?*c.WC_RNG) c_int;
extern fn curve448_export_public(k: ?*c.curve448_key, out32: [*c]u8, outLen: [*c]c.word32) c_int;
extern fn curve448_import_public(k: ?*c.curve448_key, in32: [*c]const u8, inLen: c.word32) c_int;
extern fn curve448_shared_secret(myPriv: ?*c.curve448_key, theirPub: ?*c.curve448_key, out: [*c]u8, outLen: [*c]c.word32) c_int;
extern fn curve448_export_private(k: ?*c.curve448_key, out: [*c]u8, len: [*c]c.word32) c_int;

pub fn main() !void {
    const ECC_448_BIT_FIELD = 56;
    // 448-bit curve field
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
    const alice = curve448_new() orelse return error.OutOfMemory;
    defer _ = curve448_delete(alice);

    const bob = curve448_new() orelse return error.OutOfMemory;
    defer _ = curve448_delete(bob);

    try wcOk(curve448_make_key(alice, &rng), "alice make key");
    try wcOk(curve448_make_key(bob, &rng), "bob make key");

    // Export public keys
    var alice_public: [ECC_448_BIT_FIELD]u8 = undefined;
    var bob_public: [ECC_448_BIT_FIELD]u8 = undefined;

    var alice_public_len: c.word32 = ECC_448_BIT_FIELD;
    var bob_public_len: c.word32 = ECC_448_BIT_FIELD;

    try wcOk(curve448_export_public(alice, alice_public[0..].ptr, &alice_public_len), "export alice pub");
    try wcOk(curve448_export_public(bob, bob_public[0..].ptr, &bob_public_len), "export bob pub");

    // Import keys
    const get_alice_public = curve448_new() orelse return error.OutOfMemory;
    defer _ = curve448_delete(get_alice_public);

    const get_bob_public = curve448_new() orelse return error.OutOfMemory;
    defer _ = curve448_delete(get_bob_public);

    try wcOk(curve448_import_public(get_alice_public, bob_public[0..].ptr, bob_public_len), "alice import bob");
    try wcOk(curve448_import_public(get_bob_public, alice_public[0..].ptr, alice_public_len), "bob import alice");

    // Compute shared secret
    var alice_secret: [ECC_448_BIT_FIELD]u8 = undefined;
    var bob_secret: [ECC_448_BIT_FIELD]u8 = undefined;

    var alice_secret_len: c.word32 = ECC_448_BIT_FIELD;
    var bob_secret_len: c.word32 = ECC_448_BIT_FIELD;

    try wcOk(curve448_shared_secret(alice, get_alice_public, alice_secret[0..].ptr, &alice_secret_len), "alice secret");
    try wcOk(curve448_shared_secret(bob, get_bob_public, bob_secret[0..].ptr, &bob_secret_len), "bob secret");

    // Export private keys
    var alice_private: [ECC_448_BIT_FIELD]u8 = undefined;
    var bob_private: [ECC_448_BIT_FIELD]u8 = undefined;

    var alice_private_len: c.word32 = ECC_448_BIT_FIELD;
    var bob_private_len: c.word32 = ECC_448_BIT_FIELD;

    try wcOk(curve448_export_private(alice, alice_private[0..].ptr, &alice_private_len), "alice export private");
    try wcOk(curve448_export_private(bob, bob_private[0..].ptr, &bob_private_len), "bob export private");

    try stdout.print("== X448 ==\n\n", .{});
    try stdout.print("Alice private key:\t{x}\n", .{alice_private[0..alice_private_len]});
    try stdout.print("Alice public key:\t{x}\n\n", .{alice_public[0..alice_public_len]});

    try stdout.print("Bob private key:\t{x}\n", .{bob_private[0..bob_private_len]});
    try stdout.print("Bob public key:\t\t{x}\n\n", .{bob_public[0..bob_public_len]});

    try stdout.print("Bob shared key:\t\t{x} \n", .{bob_secret[0..bob_secret_len]});
    try stdout.print("Alice shared key:\t{x}\n\n", .{alice_secret[0..alice_secret_len]});
    try stdout.flush();
}
