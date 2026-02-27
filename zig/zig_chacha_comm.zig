const std = @import("std");
const crypto = std.crypto;
const aead = @import("std").crypto.aead;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var m: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m = args[1];
    }

    var Bob_nonce: [aead.chacha_poly.ChaCha20Poly1305.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&Bob_nonce);
    var Alice_nonce: [aead.chacha_poly.ChaCha20Poly1305.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&Alice_nonce);

    const ciphertext = try allocator.alloc(u8, m.len);
    defer allocator.free(ciphertext);

    var Bob_Key: [32]u8 = undefined;
    var Alice_Key: [32]u8 = undefined;

    crypto.random.bytes(&Bob_Key);
    crypto.random.bytes(&Alice_Key);

    crypto.stream.chacha.ChaCha12IETF.xor(ciphertext, m, 0, Bob_Key, Bob_nonce);
    crypto.stream.chacha.ChaCha12IETF.xor(ciphertext, ciphertext, 0, Alice_Key, Alice_nonce);

    const m2 = try allocator.alloc(u8, m.len);
    defer allocator.free(m2);

    const ct = ciphertext;
    crypto.stream.chacha.ChaCha12IETF.xor(ct, ct, 0, Bob_Key, Bob_nonce);
    crypto.stream.chacha.ChaCha12IETF.xor(m2, ct, 0, Alice_Key, Alice_nonce);

    try stdout.print("ChaCha20 Commutative Encryption\n", .{});
    try stdout.print("Encrypt with Bob's key, then Alice's, and then decrypt with Bob key then Alice's\n", .{});
    try stdout.print("\nMessage: {s}\n", .{m});
    try stdout.print("\nBob Key:\t{x} \n", .{Bob_Key});
    try stdout.print("  Bob Nonce:\t\t{x} \n", .{Bob_nonce});
    try stdout.print("\nAlice Key:\t{x} \n", .{Alice_Key});
    try stdout.print("  Alice Nonce:\t\t{x} \n", .{Alice_nonce});

    try stdout.print("\nCiphertext: {x} \n", .{ciphertext});

    try stdout.print("\nDecrypted: {s} \n", .{m2});
    try stdout.flush();
}
