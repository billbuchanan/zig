const std = @import("std");
const crypto = @import("std").crypto;
const aead = @import("std").crypto.aead;

pub fn main() !void {
    var message: []u8 = undefined;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    var Alice_private: [32]u8 = undefined;
    crypto.random.bytes(&Alice_private);
    const Alice_public = try crypto.ecc.P256.basePoint.mul(Alice_private, std.builtin.Endian.big);

    var r: [32]u8 = undefined;
    crypto.random.bytes(&r);

    const R = try crypto.ecc.P256.basePoint.mul(r, std.builtin.Endian.big);

    const S = try crypto.ecc.P256.mul(Alice_public, r, std.builtin.Endian.big);

    // Derive a 32-bit key with HKDF-Sha256
    var derived_key: [32]u8 = undefined;

    var prk = crypto.kdf.hkdf.HkdfSha256.extract("Salty", S.toCompressedSec1()[0..32]);
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key, "content", prk);

    // Let's encrypt with derived key

    var nonce: [aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ad = "Add";

    const ciphertext = try allocator.alloc(u8, message.len);
    defer allocator.free(ciphertext);

    var tag: [aead.aes_gcm.Aes128Gcm.tag_length]u8 = undefined;

    aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &tag, message, ad, nonce, derived_key);

    // Alice now derives key

    const K = try crypto.ecc.P256.mul(R, Alice_private, std.builtin.Endian.big);

    var derived_key2: [32]u8 = undefined;
    prk = crypto.kdf.hkdf.HkdfSha256.extract("Salty", K.toCompressedSec1()[0..32]);
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key2, "content", prk);

    const m2 = try allocator.alloc(u8, message.len);
    defer allocator.free(m2);

    try aead.aes_gcm.Aes256Gcm.decrypt(m2, ciphertext, tag, ad, nonce, derived_key2);

    try stdout.print("ECIES with P256\n", .{});

    try stdout.print("\nMessage:\t{s}\n", .{message});

    try stdout.print("\nAlice secret key:\t{x}\n", .{Alice_private});
    try stdout.print("Alice public key:\t{x}\n", .{Alice_public.toCompressedSec1()});

    try stdout.print("\nR:\t{x}\n", .{R.toCompressedSec1()});
    try stdout.print("\nS:\t{x}\n", .{S.toCompressedSec1()});

    try stdout.print("\nDerived key for Bob: {x}\n", .{derived_key});
    try stdout.print("\nCiphertext:\t{x}\n", .{ciphertext});

    try stdout.print("\nK:\t{x}\n", .{K.toCompressedSec1()});
    try stdout.print("\nDerived key for Alice: {x}\n", .{derived_key2});
    try stdout.print("\nDecrypted:\t{s}\n", .{m2});
    try stdout.flush();
}
