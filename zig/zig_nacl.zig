const std = @import("std");
const nacl = @import("std").crypto.nacl;
const crypto = @import("std").crypto;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var message: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    const BobKeyPair = nacl.Box.KeyPair.generate();
    const AliceKeyPair = nacl.Box.KeyPair.generate();

    var salt: [24]u8 = undefined;
    crypto.random.bytes(&salt);

    const ciphertext_size = message.len + @as(usize, nacl.Box.tag_length);
    const ciphertext = try allocator.alloc(u8, ciphertext_size);
    defer allocator.free(ciphertext);

    const plaintext = try allocator.alloc(u8, message.len);
    defer allocator.free(plaintext);

    try nacl.Box.seal(ciphertext, message, salt, AliceKeyPair.public_key, BobKeyPair.secret_key);
    try nacl.Box.open(plaintext, ciphertext, salt, BobKeyPair.public_key, AliceKeyPair.secret_key);

    try stdout.print("== Box encryption Message: {s} \n", .{message});
    try stdout.print("== Box encryption Salt: {x} \n", .{salt});
    try stdout.print("\nBob Secret Key: {x} \n", .{BobKeyPair.secret_key});
    try stdout.print("Bob Public Key: {x}\n", .{BobKeyPair.public_key});
    try stdout.print("\nAlice Secret Key: {x} \n", .{AliceKeyPair.secret_key});
    try stdout.print("Alice Public Key: {x}\n", .{AliceKeyPair.public_key});

    try stdout.print("\nCiphertext passed to Alice (using Alice's public key): {x}\n", .{ciphertext});
    try stdout.print("\nPlaintext recovered by Alice (with her private key): {s}\n", .{plaintext});

    try stdout.flush();
}
