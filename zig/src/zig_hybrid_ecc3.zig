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

    const Alice_keypair = crypto.dh.X25519.KeyPair.generate();

    var r: [32]u8 = undefined;
    crypto.random.bytes(&r);

    const R = try crypto.dh.X25519.scalarmult(r, crypto.dh.X25519.Curve.basePoint.toBytes());

    const S = try crypto.dh.X25519.scalarmult(r, Alice_keypair.public_key);

    // Derive a 32-bit key with HKDF-Sha256
    var derived_key: [32]u8 = undefined;

    var prk = crypto.kdf.hkdf.HkdfSha256.extract("Salty", S[0..32]);
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

    const K = try crypto.dh.X25519.scalarmult(Alice_keypair.secret_key, R);

    var derived_key2: [32]u8 = undefined;
    prk = crypto.kdf.hkdf.HkdfSha256.extract("Salty", K[0..32]);
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key2, "content", prk);

    const m2 = try allocator.alloc(u8, message.len);
    defer allocator.free(m2);

    try aead.aes_gcm.Aes256Gcm.decrypt(m2, ciphertext, tag, ad, nonce, derived_key2);

    try stdout.print("ECIES with X25519\n", .{});

    try stdout.print("\nMessage:\t{s}\n", .{message});

    try stdout.print("\nAlice secret key:\t{x}\n", .{Alice_keypair.secret_key});
    try stdout.print("Alice public key:\t{x}\n", .{Alice_keypair.public_key});

    try stdout.print("\nR:\t{x}\n", .{R});
    try stdout.print("\nS:\t{x}\n", .{S});

    try stdout.print("\nDerived key for Bob: {x}\n", .{derived_key});
    try stdout.print("\nCiphertext:\t{x}\n", .{ciphertext});

    try stdout.print("\nK:\t{x}\n", .{K});
    try stdout.print("\nDerived key for Alice: {x}\n", .{derived_key2});
    try stdout.print("\nDecrypted:\t{s}\n", .{m2});
    try stdout.flush();
}
